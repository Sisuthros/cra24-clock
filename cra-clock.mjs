#!/usr/bin/env node
'use strict';

/**
 * cra-clock.mjs — CRA Article 14 clock and evidence chain.
 *
 * THE PROBLEM: from 11 September 2026, an EU manufacturer must report an
 * actively exploited vulnerability to ENISA and the coordinating CSIRT
 * within 24 hours, give a more detailed assessment within 72 hours, and a
 * final report within 14 days. The duty also covers products already sold.
 *
 * The clock starts at AWARENESS, not confirmation. After the fact, a
 * supervisor asks three things, all of them evidence questions:
 *   1. When exactly did you become aware?
 *   2. Who decided this was active exploitation?
 *   3. Did the notification go out exactly once?
 *
 * ENISA's Single Reporting Platform has no API, so submit and retry are
 * human steps. Duplicate notification is a real risk, and so is a timestamp
 * you cannot defend.
 *
 * WHAT THIS DOES: records the awareness moment, computes the three
 * deadlines, produces pre-filled drafts, and keeps a hash-chained log that
 * cannot be edited after the fact without detection. A submission is marked
 * EXACTLY ONCE per stage.
 *
 * WHAT THIS DOES NOT DO: it does not send anything to an authority, does
 * not decide for you whether a vulnerability is actively exploited, is not
 * legal advice, and does not scan code. All data stays on your machine.
 *
 * Usage:
 *   node cra-clock.mjs deadlines --aware 2026-09-11T08:00:00Z
 *   node cra-clock.mjs aware --product "Acme FW" --vuln CVE-2026-1234 --source <url> --decided-by "name"
 *   node cra-clock.mjs draft  --id <id> --stage early|detailed|final
 *   node cra-clock.mjs submitted --id <id> --stage early --ref SRP-123
 *   node cra-clock.mjs status [--json]
 *   node cra-clock.mjs verify
 *
 * Exit: 0 = ok · 1 = chain broken or duplicate submit blocked · 2 = usage error
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildAdvisory, validateAdvisory } from './csaf.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LOG = process.env.CRA_CLOCK_LOG
  ? path.resolve(process.env.CRA_CLOCK_LOG)
  : path.join(HERE, 'data', 'cra-events.jsonl');

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/**
 * CRA Article 14 cascade. Pure function: same input, same output, always.
 *
 * The first two deadlines are counted from awareness. The final report is
 * not: the regulation ties it to the moment a corrective measure becomes
 * available. Until that moment is known, the deadline does not exist, and
 * the tool says so rather than inventing a date.
 *
 * Fixed 2026-09-04: previously `final.due` was awareness + 336 h. That
 * always produced too early a deadline when the fix landed later than
 * 14 days after awareness, which is the exact error this tool exists to stop.
 */
export function deadlines(awareIso, remediationIso = null) {
  const t = new Date(awareIso).getTime();
  if (Number.isNaN(t)) throw new Error(`timestamp does not parse: ${awareIso}`);
  const at = (base, h) => new Date(base + h * 3600_000).toISOString();

  let r = null;
  if (remediationIso != null && remediationIso !== '') {
    r = new Date(remediationIso).getTime();
    if (Number.isNaN(r)) throw new Error(`remediation timestamp does not parse: ${remediationIso}`);
    if (r < t) throw new Error('remediation cannot be available before awareness began');
  }

  return {
    aware_at: new Date(t).toISOString(),
    remediation_available_at: r === null ? null : new Date(r).toISOString(),
    early_warning: { stage: 'early', due: at(t, 24), hours: 24, basis: 'aware_at', pending: false, what: 'Early warning to ENISA and the coordinating CSIRT' },
    detailed: { stage: 'detailed', due: at(t, 72), hours: 72, basis: 'aware_at', pending: false, what: 'More detailed assessment, corrective measures' },
    final: r === null
      ? {
          stage: 'final', due: null, hours: 336, basis: 'remediation_available_at', pending: true,
          earliest_possible: at(t, 336),
          what: 'Final report. The deadline starts only when a corrective measure is available, so it cannot be computed yet.',
        }
      : {
          stage: 'final', due: at(r, 336), hours: 336, basis: 'remediation_available_at', pending: false,
          earliest_possible: at(t, 336),
          what: 'Final report after a corrective measure became available',
        },
  };
}

/** Displayable deadline when one may not exist. Never an invented date. */
export function dueText(stageObj) {
  if (stageObj.due) return stageObj.due;
  return `not yet computable (earliest ${stageObj.earliest_possible}, starts when remediation is available)`;
}

function readLog() {
  if (!existsSync(LOG)) return [];
  const rows = [];
  for (const line of readFileSync(LOG, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { rows.push(JSON.parse(line)); } catch { rows.push({ __broken: line.slice(0, 60) }); }
  }
  return rows;
}

/**
 * Write a hash-chained row and read it back. Each row binds to its
 * predecessor, so changing one line later breaks the chain and `verify`
 * sees it. This is the part a form fill does not give you.
 */
function appendChained(entry) {
  mkdirSync(path.dirname(LOG), { recursive: true });
  const rows = readLog();
  const prev = rows.length ? rows[rows.length - 1].entry_sha256 : ''.padEnd(64, '0');
  const body = { ...entry, at: entry.at ?? new Date().toISOString(), prev_sha256: prev };
  const entry_sha256 = sha256(JSON.stringify(body));
  const full = { ...body, entry_sha256 };
  appendFileSync(LOG, `${JSON.stringify(full)}\n`, 'utf8');
  const back = readLog().find((r) => r.entry_sha256 === entry_sha256);
  if (!back) { console.error('🛑 cra-clock: row did not round-trip — do not claim this was recorded.'); process.exit(1); }
  return full;
}

export function verifyChain(rows) {
  const problems = [];
  let prev = ''.padEnd(64, '0');
  for (const [i, r] of rows.entries()) {
    if (r.__broken) { problems.push(`row ${i + 1}: does not parse as JSON`); continue; }
    if (r.prev_sha256 !== prev) problems.push(`row ${i + 1}: prev_sha256 does not match the previous row`);
    const { entry_sha256, ...body } = r;
    if (sha256(JSON.stringify(body)) !== entry_sha256) problems.push(`row ${i + 1}: content changed after recording`);
    prev = entry_sha256;
  }
  return { ok: problems.length === 0, problems, count: rows.length };
}

const STAGES = ['early', 'detailed', 'final'];

/** Pre-filled draft. Mandatory fields the buyer cannot forget. */
function draftFor(ev, stage) {
  const rem = remediationFor(ev.id);
  const d = deadlines(ev.aware_at, rem);
  const st = d[stage === 'early' ? 'early_warning' : stage];
  const lines = [
    `CRA Article 14 — ${stage === 'early' ? 'EARLY WARNING (24 h)' : stage === 'detailed' ? 'DETAILED ASSESSMENT (72 h)' : 'FINAL REPORT (14 days from remediation)'}`,
    ``,
    `Product: ${ev.product}`,
    `Vulnerability: ${ev.vuln}`,
    `Awareness began: ${ev.aware_at}`,
    `Deadline: ${dueText(st)}`,
    `Assessment made by: ${ev.decided_by}`,
    `Source: ${ev.source}`,
    ``,
    `Actively exploited: ${ev.actively_exploited ? 'YES' : '<<FILL: yes/no and rationale>>'}`,
    `Member States where the product is available: <<FILL>>`,
  ];
  if (stage !== 'early') lines.push(`Corrective or mitigating measures: <<FILL>>`, `Impact assessment: <<FILL>>`);
  if (stage === 'final') {
    lines.push(
      rem
        ? `Remediation available from: ${rem}  (recorded in the evidence chain)`
        : `Remediation available from: <<FILL — record it with: cra-clock.mjs remediation --id ${ev.id.slice(0, 8)} --at <ISO>>>`,
      `Distribution method to users: <<FILL>>`
    );
  }
  lines.push(
    ``,
    `Event id: ${ev.id}`,
    `Evidence chain: ${path.relative(process.cwd(), LOG)}`,
    ``,
    `This is a draft. It is not legal advice, and this tool does not send`,
    `anything to an authority. Submission is done on ENISA's Single Reporting Platform.`
  );
  return lines.join('\n');
}

const events = () => readLog().filter((r) => r.type === 'aware');
const findEvent = (id) => events().find((e) => e.id === id || e.id.startsWith(id));

/** Latest recorded remediation-available moment, or null. This decides the final-report deadline. */
function remediationFor(eventId) {
  const rows = readLog().filter((r) => r.type === 'remediation' && r.event_id === eventId);
  return rows.length ? rows[rows.length - 1].available_at : null;
}

// --------------------------------------------------------------------------

if (cmd === 'deadlines') {
  const aware = flag('aware');
  if (!aware) { console.error('Usage: deadlines --aware <ISO-timestamp>'); process.exit(2); }
  let d;
  try { d = deadlines(aware, flag('remediation')); } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  if (argv.includes('--json')) { console.log(JSON.stringify(d, null, 2)); }
  else {
    console.log(`Awareness began: ${d.aware_at}`);
    if (d.remediation_available_at) console.log(`Remediation available: ${d.remediation_available_at}`);
    for (const k of ['early_warning', 'detailed', 'final']) {
      const s = d[k];
      console.log(`  ${String(s.hours).padStart(3)} h  ${dueText(s)}  ${s.what}`);
    }
  }
} else if (cmd === 'aware') {
  const product = flag('product'); const vuln = flag('vuln');
  const source = flag('source'); const decidedBy = flag('decided-by');
  if (!product || !vuln || !source || !decidedBy) {
    console.error('Usage: aware --product <name> --vuln <id> --source <url> --decided-by <name> [--aware <ISO>] [--actively-exploited]');
    process.exit(2);
  }
  const awareAt = flag('aware') ?? new Date().toISOString();
  try { deadlines(awareAt); } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  const ev = appendChained({
    type: 'aware', id: randomUUID(), product, vuln, source, decided_by: decidedBy,
    aware_at: new Date(awareAt).toISOString(),
    actively_exploited: argv.includes('--actively-exploited'),
  });
  const d = deadlines(ev.aware_at);
  console.log(`RECORDED ${ev.id}`);
  console.log(`  awareness: ${ev.aware_at}   assessed by: ${ev.decided_by}`);
  for (const k of ['early_warning', 'detailed', 'final']) console.log(`  ${String(d[k].hours).padStart(3)} h  ${dueText(d[k])}`);
  console.log(`  chain digest: ${ev.entry_sha256.slice(0, 16)}…`);
} else if (cmd === 'draft') {
  const id = flag('id'); const stage = flag('stage');
  if (!id || !STAGES.includes(stage)) { console.error(`Usage: draft --id <id> --stage ${STAGES.join('|')}`); process.exit(2); }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 event not found: ${id}`); process.exit(2); }
  console.log(draftFor(ev, stage));
} else if (cmd === 'submitted') {
  const id = flag('id'); const stage = flag('stage'); const ref = flag('ref');
  if (!id || !STAGES.includes(stage) || !ref) { console.error(`Usage: submitted --id <id> --stage ${STAGES.join('|')} --ref <SRP-reference>`); process.exit(2); }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 event not found: ${id}`); process.exit(2); }
  // EXACTLY ONCE. This is the product promise: the same stage is not
  // recorded twice, even if the command is re-run or the script restarts
  // after a crash. A second attempt is an error, not a silent skip.
  const already = readLog().find((r) => r.type === 'submitted' && r.event_id === ev.id && r.stage === stage);
  if (already) {
    console.error(`🛑 BLOCKED: ${stage} already marked submitted at ${already.at} (ref ${already.ref}).`);
    console.error('   A second notification for the same stage is exactly what this tool prevents.');
    process.exit(1);
  }
  const row = appendChained({ type: 'submitted', event_id: ev.id, stage, ref });
  console.log(`SUBMISSION MARKED ${stage} — ${ref}`);
  console.log(`  chain digest: ${row.entry_sha256.slice(0, 16)}…`);
} else if (cmd === 'remediation') {
  // The final-report deadline starts from this moment, not from awareness.
  const id = flag('id'); const at = flag('at');
  if (!id || !at) { console.error('Usage: remediation --id <id> --at <ISO-timestamp>'); process.exit(2); }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 event not found: ${id}`); process.exit(2); }
  let d;
  try { d = deadlines(ev.aware_at, at); } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  const row = appendChained({ type: 'remediation', event_id: ev.id, available_at: d.remediation_available_at });
  console.log(`REMEDIATION AVAILABLE RECORDED ${d.remediation_available_at}`);
  console.log(`  final-report deadline: ${d.final.due}`);
  console.log(`  chain digest: ${row.entry_sha256.slice(0, 16)}…`);
} else if (cmd === 'status') {
  const rows = readLog();
  const evs = events();
  const now = Date.now();
  const out = evs.map((ev) => {
    const rem = remediationFor(ev.id);
    const d = deadlines(ev.aware_at, rem);
    const stages = STAGES.map((s) => {
      const key = s === 'early' ? 'early_warning' : s;
      const sub = rows.find((r) => r.type === 'submitted' && r.event_id === ev.id && r.stage === s);
      const st = d[key];
      // Without a deadline there is no overdue. Unknown is not the same as late.
      if (st.due === null) {
        return { stage: s, due: null, pending: true, earliest_possible: st.earliest_possible, submitted: Boolean(sub), ref: sub?.ref ?? '', overdue: false, hours_left: null };
      }
      const due = new Date(st.due).getTime();
      return { stage: s, due: st.due, pending: false, submitted: Boolean(sub), ref: sub?.ref ?? '', overdue: !sub && now > due, hours_left: Number(((due - now) / 3600_000).toFixed(1)) };
    });
    return { id: ev.id, product: ev.product, vuln: ev.vuln, aware_at: ev.aware_at, remediation_available_at: rem, stages };
  });
  if (argv.includes('--json')) { console.log(JSON.stringify({ events: out, chain: verifyChain(rows) }, null, 2)); }
  else if (!out.length) { console.log('No recorded events.'); }
  else {
    for (const e of out) {
      console.log(`${e.id.slice(0, 8)}  ${e.product} — ${e.vuln}   awareness ${e.aware_at}`);
      for (const s of e.stages) {
        const mark = s.submitted ? '✅' : s.overdue ? '🔴' : s.pending ? '⏳' : '·';
        const tail = s.submitted
          ? `submitted (${s.ref})`
          : s.overdue ? 'OVERDUE'
          : s.pending ? 'waiting for remediation to be available'
          : `${s.hours_left} h remaining`;
        const due = s.due ?? `earliest ${s.earliest_possible}`;
        console.log(`   ${mark} ${s.stage.padEnd(9)} ${due}  ${tail}`);
      }
    }
    const v = verifyChain(rows);
    console.log(`\nevidence chain: ${v.ok ? 'intact' : 'BROKEN'} (${v.count} rows)`);
  }
} else if (cmd === 'csaf') {
  // CSAF 2.0 advisory from a recorded event. Publisher is not invented:
  // without a name and namespace, no file is produced.
  const id = flag('id');
  const name = flag('publisher');
  const ns = flag('namespace');
  if (!id || !name || !ns) {
    console.error('Usage: csaf --id <id> --publisher "<name>" --namespace https://example.com [--status draft|interim|final] [--version 1.0.0]');
    process.exit(2);
  }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 event not found: ${id}`); process.exit(2); }
  let doc;
  try {
    doc = buildAdvisory({ event: ev, publisherName: name, publisherNamespace: ns, status: flag('status', 'draft'), version: flag('version', '1.0.0') });
  } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  const v = validateAdvisory(doc);
  if (!v.ok) {
    // An invalid CSAF is worse than a missing one: it claims to be an advisory.
    console.error('🛑 produced advisory does not meet CSAF 2.0 mandatory fields:');
    for (const e of v.errors) console.error(`   ✗ ${e}`);
    process.exit(1);
  }
  console.log(JSON.stringify(doc, null, 2));
} else if (cmd === 'verify') {
  const v = verifyChain(readLog());
  if (v.ok) { console.log(`✅ evidence chain intact — ${v.count} rows`); }
  else {
    console.log(`🛑 evidence chain BROKEN — ${v.problems.length} problem(s):`);
    for (const p of v.problems) console.log(`  ✗ ${p}`);
    process.exit(1);
  }
} else {
  console.error('Commands: deadlines | aware | draft | submitted | csaf | status | verify');
  process.exit(2);
}
