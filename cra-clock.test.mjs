#!/usr/bin/env node
'use strict';

/**
 * cra-clock.test.mjs — the product promises as tests.
 *
 * Each test answers one question a supervisor asks after the fact:
 * when the clock started, whether the notification went out exactly once,
 * and whether the log can be edited unnoticed. If any of these is red,
 * the product must not be sold.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLOCK = resolve(HERE, 'cra-clock.mjs');
const TMP = mkdtempSync(resolve(tmpdir(), 'cra-clock-'));
const LOG = resolve(TMP, 'events.jsonl');
const env = { ...process.env, CRA_CLOCK_LOG: LOG };

let pass = 0;
const fail = [];
const check = (name, cond, detail = '') => {
  if (cond) { pass += 1; console.log(`  ok   ${name}`); }
  else { fail.push(name); console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`); }
};
function run(...args) {
  try { return { code: 0, out: execFileSync(process.execPath, [CLOCK, ...args], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) }; }
  catch (e) { return { code: e.status ?? 1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` }; }
}
const log = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8').trim().split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l)) : []);

console.log(`cra-clock: state ${TMP}\n`);

// 1. Deadlines match CRA Article 14 and are deterministic.
let r = run('deadlines', '--aware', '2026-09-11T08:00:00Z', '--json');
let d = JSON.parse(r.out);
check('24 h early warning', d.early_warning.due === '2026-09-12T08:00:00.000Z', d.early_warning.due);
check('72 h detailed assessment', d.detailed.due === '2026-09-14T08:00:00.000Z', d.detailed.due);
// CRA Article 14: the final-report deadline does NOT start at awareness but
// when a corrective measure is available (Reg (EU) 2024/2847 art. 14).
// Without a remediation date there is no deadline, and the tool says
// "pending" rather than inventing a day.
check('final report is pending without a remediation date', d.final.due === null && d.final.pending === true && d.final.earliest_possible === '2026-09-25T08:00:00.000Z', JSON.stringify(d.final));
const rRem = run('deadlines', '--aware', '2026-09-11T08:00:00Z', '--remediation', '2026-10-01T08:00:00Z', '--json');
const dRem = JSON.parse(rRem.out);
check('final report = remediation + 14 days', dRem.final.due === '2026-10-15T08:00:00.000Z', dRem.final.due);
const r2 = run('deadlines', '--aware', '2026-09-11T08:00:00Z', '--json');
check('same input produces the same output', r.out === r2.out);
check('invalid timestamp is rejected', run('deadlines', '--aware', 'yesterday').code === 2);

// 2. Awareness is recorded and gets an id.
r = run('aware', '--product', 'Acme FW', '--vuln', 'CVE-2026-1234', '--source', 'https://example.invalid/adv', '--decided-by', 'Alex', '--aware', '2026-09-11T08:00:00Z');
const id = (/RECORDED (\S+)/.exec(r.out) ?? [])[1];
check('awareness is recorded', r.code === 0 && Boolean(id), r.out.slice(0, 120));
check('log has an aware row', log().filter((x) => x.type === 'aware').length === 1);
check('incomplete command is rejected', run('aware', '--product', 'X').code === 2);

// 3. Draft contains mandatory fields and does not claim to be legal advice.
r = run('draft', '--id', id, '--stage', 'early');
check('draft contains the awareness moment', r.out.includes('2026-09-11T08:00:00.000Z'), r.out.slice(0, 120));
check('draft marks fields to fill', r.out.includes('<<FILL'), r.out.slice(0, 200));
check('draft denies being legal advice', /not legal advice/.test(r.out));
check('draft says it does not send anything', /does not send/.test(r.out.replace(/\s+/g, ' ')), r.out.slice(-220));
r = run('draft', '--id', id, '--stage', 'final');
check('final report asks when remediation is available', /Remediation available from/.test(r.out));

// 4. EXACTLY ONCE — the core product promise.
r = run('submitted', '--id', id, '--stage', 'early', '--ref', 'SRP-1');
check('first submission is marked', r.code === 0 && /SUBMISSION MARKED/.test(r.out), r.out.slice(0, 120));
r = run('submitted', '--id', id, '--stage', 'early', '--ref', 'SRP-2');
check('second submission of the same stage is BLOCKED', r.code === 1 && /BLOCKED/.test(r.out), r.out.slice(0, 160));
check('blocked attempt did not enter the log', log().filter((x) => x.type === 'submitted' && x.stage === 'early').length === 1);
r = run('submitted', '--id', id, '--stage', 'detailed', '--ref', 'SRP-3');
check('a different stage gets its own mark', r.code === 0);

// 5. Evidence chain is tamper-evident.
check('chain intact before tampering', run('verify').code === 0);
const rows = log();
check('every row has prev_sha256', rows.every((x) => typeof x.prev_sha256 === 'string' && x.prev_sha256.length === 64));
check('first row chains to zero', rows[0].prev_sha256 === ''.padEnd(64, '0'));
const tampered = rows.map((x, i) => (i === 0 ? { ...x, aware_at: '2026-09-12T08:00:00.000Z' } : x));
writeFileSync(LOG, tampered.map((x) => JSON.stringify(x)).join('\n') + '\n', 'utf8');
r = run('verify');
check('moved timestamp is detected', r.code === 1 && /BROKEN/.test(r.out), r.out.slice(0, 160));
check('error names the changed row', /content changed/.test(r.out), r.out.slice(0, 200));

// 6. status reports overdue.
writeFileSync(LOG, rows.map((x) => JSON.stringify(x)).join('\n') + '\n', 'utf8');
r = run('status', '--json');
const st = JSON.parse(r.out);
const ev = st.events[0];
check('status lists three stages', ev.stages.length === 3);
check('submitted stage is marked', ev.stages.find((s) => s.stage === 'early').submitted === true);
check('a future deadline is not overdue', ev.stages.find((s) => s.stage === 'final').overdue === false);
check('status reports the chain as intact', st.chain.ok === true);

r = run('aware', '--product', 'Legacy', '--vuln', 'CVE-2020-0001', '--source', 'https://example.invalid/old', '--decided-by', 'Alex', '--aware', '2020-01-01T00:00:00Z');
const oldId = (/RECORDED (\S+)/.exec(r.out) ?? [])[1];
const st2 = JSON.parse(run('status', '--json').out);
const oldEv = st2.events.find((e) => e.id === oldId);
const oldStage = (s) => oldEv.stages.find((x) => x.stage === s);
check('elapsed fixed deadlines are overdue (early + detailed)', oldStage('early').overdue === true && oldStage('detailed').overdue === true, JSON.stringify(oldEv.stages));
check('final report is not overdue without a remediation date (pending)', oldStage('final').overdue === false && oldStage('final').pending === true, JSON.stringify(oldStage('final')));
check('overdue stages are not marked submitted', oldEv.stages.every((s) => s.submitted === false));

// 7. CSAF 2.0 export. An invalid advisory is worse than a missing one.
r = run('csaf', '--id', id, '--publisher', 'Acme Ltd', '--namespace', 'https://acme.example', '--status', 'final');
check('csaf export succeeds', r.code === 0, r.out.slice(0, 160));
const adv = JSON.parse(r.out);
for (const k of ['category', 'csaf_version', 'publisher', 'title', 'tracking']) {
  check(`/document/${k} exists`, adv.document[k] !== undefined);
}
for (const k of ['current_release_date', 'id', 'initial_release_date', 'revision_history', 'status', 'version']) {
  check(`/document/tracking/${k} exists`, adv.document.tracking[k] !== undefined);
}
check('csaf_version is 2.0', adv.document.csaf_version === '2.0', adv.document.csaf_version);
check('revision_history row has date, number, summary', ['date', 'number', 'summary'].every((k) => adv.document.tracking.revision_history[0][k]));
check('profile requires product_tree', Boolean(adv.product_tree));
check('profile requires vulnerabilities', Array.isArray(adv.vulnerabilities) && adv.vulnerabilities.length > 0);
check('CVE id goes into the cve field', adv.vulnerabilities[0].cve === 'CVE-2026-1234', JSON.stringify(adv.vulnerabilities[0]).slice(0, 120));
check('advisory carries the awareness moment', JSON.stringify(adv).includes('2026-09-11T08:00:00.000Z'));
check('advisory names who made the assessment', JSON.stringify(adv).includes('Alex'));

check('no advisory without a namespace', run('csaf', '--id', id, '--publisher', 'Acme Ltd').code === 2);
r = run('csaf', '--id', id, '--publisher', 'Acme Ltd', '--namespace', 'acme.example');
check('namespace must be a URL', r.code === 2 && /URL/.test(r.out), r.out.slice(0, 120));

r = run('aware', '--product', 'Acme', '--vuln', 'ACME-2026-9', '--source', 'https://example.invalid/x', '--decided-by', 'Alex', '--aware', '2026-09-11T08:00:00Z');
const vid = (/RECORDED (\S+)/.exec(r.out) ?? [])[1];
const adv2 = JSON.parse(run('csaf', '--id', vid, '--publisher', 'Acme Ltd', '--namespace', 'https://acme.example').out);
check('vendor id goes into the ids field', adv2.vulnerabilities[0].cve === undefined && Array.isArray(adv2.vulnerabilities[0].ids), JSON.stringify(adv2.vulnerabilities[0]).slice(0, 140));

rmSync(TMP, { recursive: true, force: true });

console.log(`\n${pass} ok, ${fail.length} fail`);
if (fail.length) { console.log('failed:'); for (const f of fail) console.log(`  - ${f}`); process.exit(1); }
