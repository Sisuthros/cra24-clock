#!/usr/bin/env node
'use strict';

/**
 * cra-clock.test.mjs — tuotteen lupaukset testeinä.
 *
 * Jokainen testi vastaa yhteen kysymykseen jonka valvoja esittää jälkikäteen:
 * milloin kello alkoi, lähtikö ilmoitus tasan kerran, ja voiko lokia muokata
 * huomaamatta. Jos jokin näistä on punainen, tuotetta ei saa myydä.
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

console.log(`cra-clock: tila ${TMP}\n`);

// 1. Määräajat ovat CRA 14 art. mukaiset ja deterministiset.
let r = run('deadlines', '--aware', '2026-09-11T08:00:00Z', '--json');
let d = JSON.parse(r.out);
check('24 h ennakkovaroitus', d.early_warning.due === '2026-09-12T08:00:00.000Z', d.early_warning.due);
check('72 h tarkempi arvio', d.detailed.due === '2026-09-14T08:00:00.000Z', d.detailed.due);
check('14 vrk loppuraportti', d.final.due === '2026-09-25T08:00:00.000Z', d.final.due);
const r2 = run('deadlines', '--aware', '2026-09-11T08:00:00Z', '--json');
check('sama syöte tuottaa saman tuloksen', r.out === r2.out);
check('kelvoton aikaleima hylätään', run('deadlines', '--aware', 'eilen').code === 2);

// 2. Tietoisuushetki kirjautuu ja saa tunnuksen.
r = run('aware', '--product', 'Acme FW', '--vuln', 'CVE-2026-1234', '--source', 'https://example.invalid/adv', '--decided-by', 'Ville', '--aware', '2026-09-11T08:00:00Z');
const id = (/KIRJATTU (\S+)/.exec(r.out) ?? [])[1];
check('tietoisuus kirjautuu', r.code === 0 && Boolean(id), r.out.slice(0, 120));
check('lokissa on aware-rivi', log().filter((x) => x.type === 'aware').length === 1);
check('vajaa komento hylätään', run('aware', '--product', 'X').code === 2);

// 3. Luonnos sisältää pakolliset kentät eikä väitä olevansa oikeudellinen neuvo.
r = run('draft', '--id', id, '--stage', 'early');
check('luonnos sisältää tietoisuushetken', r.out.includes('2026-09-11T08:00:00.000Z'), r.out.slice(0, 120));
check('luonnos merkitsee täytettävät kohdat', r.out.includes('<<TÄYTÄ'), r.out.slice(0, 200));
check('luonnos kiistää olevansa oikeudellinen neuvo', /ei ole oikeudellinen neuvo/.test(r.out));
check('luonnos kertoo ettei se lähetä mitään', /työkalu lähetä/.test(r.out.replace(/\s+/g, ' ')), r.out.slice(-220));
r = run('draft', '--id', id, '--stage', 'final');
check('loppuraportti kysyy korjauksen saatavuutta', /Korjaus saatavilla alkaen/.test(r.out));

// 4. TASAN KERRAN — tuotteen ydinlupaus.
r = run('submitted', '--id', id, '--stage', 'early', '--ref', 'SRP-1');
check('ensimmäinen lähetys merkitään', r.code === 0 && /LÄHETETTY MERKITTY/.test(r.out), r.out.slice(0, 120));
r = run('submitted', '--id', id, '--stage', 'early', '--ref', 'SRP-2');
check('toinen lähetys samasta vaiheesta ESTETÄÄN', r.code === 1 && /ESTETTY/.test(r.out), r.out.slice(0, 160));
check('estetty yritys ei kirjautunut lokiin', log().filter((x) => x.type === 'submitted' && x.stage === 'early').length === 1);
r = run('submitted', '--id', id, '--stage', 'detailed', '--ref', 'SRP-3');
check('eri vaihe saa oman merkinnän', r.code === 0);

// 5. Todisteketju on peukalointikestävä.
check('ketju ehjä ennen peukalointia', run('verify').code === 0);
const rows = log();
check('jokaisella rivillä on prev_sha256', rows.every((x) => typeof x.prev_sha256 === 'string' && x.prev_sha256.length === 64));
check('ensimmäinen rivi ketjuuntuu nollaan', rows[0].prev_sha256 === ''.padEnd(64, '0'));
// Muokataan yhtä riviä jälkikäteen, kuten joku joka haluaa siirtää kelloa.
const tampered = rows.map((x, i) => (i === 0 ? { ...x, aware_at: '2026-09-12T08:00:00.000Z' } : x));
writeFileSync(LOG, tampered.map((x) => JSON.stringify(x)).join('\n') + '\n', 'utf8');
r = run('verify');
check('siirretty aikaleima havaitaan', r.code === 1 && /RIKKI/.test(r.out), r.out.slice(0, 160));
check('virhe nimeää muuttuneen rivin', /sisältö muuttunut/.test(r.out), r.out.slice(0, 200));

// 6. status kertoo myöhästymisen.
writeFileSync(LOG, rows.map((x) => JSON.stringify(x)).join('\n') + '\n', 'utf8');
r = run('status', '--json');
const st = JSON.parse(r.out);
const ev = st.events[0];
check('status listaa kolme vaihetta', ev.stages.length === 3);
check('lähetetty vaihe merkitty', ev.stages.find((s) => s.stage === 'early').submitted === true);
check('tuleva määräaika ei ole myöhässä', ev.stages.find((s) => s.stage === 'final').overdue === false);
check('status raportoi ketjun ehjäksi', st.chain.ok === true);

// Myöhästyminen testataan tapahtumalla jonka määräajat ovat OIKEASTI menneet.
// Alkuperäinen testi käytti 2026-09-11 tietoisuutta, jonka 14 vrk raja on yhä
// tulevaisuudessa — overdue:false oli siis oikea vastaus ja testi väärä.
r = run('aware', '--product', 'Vanha', '--vuln', 'CVE-2020-0001', '--source', 'https://example.invalid/old', '--decided-by', 'Ville', '--aware', '2020-01-01T00:00:00Z');
const oldId = (/KIRJATTU (\S+)/.exec(r.out) ?? [])[1];
const st2 = JSON.parse(run('status', '--json').out);
const oldEv = st2.events.find((e) => e.id === oldId);
check('menneen määräajan vaihe on myöhässä', oldEv.stages.every((s) => s.overdue === true), JSON.stringify(oldEv.stages));
check('myöhässä oleva ei ole merkitty lähetetyksi', oldEv.stages.every((s) => s.submitted === false));

// 7. CSAF 2.0 -vienti. Kelvoton neuvo on pahempi kuin puuttuva, joten
// pakolliset kentät testataan spesifikaatiota vasten eikä silmämääräisesti.
r = run('csaf', '--id', id, '--publisher', 'Acme Oy', '--namespace', 'https://acme.example', '--status', 'final');
check('csaf-vienti onnistuu', r.code === 0, r.out.slice(0, 160));
const adv = JSON.parse(r.out);
for (const k of ['category', 'csaf_version', 'publisher', 'title', 'tracking']) {
  check(`/document/${k} on olemassa`, adv.document[k] !== undefined);
}
for (const k of ['current_release_date', 'id', 'initial_release_date', 'revision_history', 'status', 'version']) {
  check(`/document/tracking/${k} on olemassa`, adv.document.tracking[k] !== undefined);
}
check('csaf_version on 2.0', adv.document.csaf_version === '2.0', adv.document.csaf_version);
check('revision_history-rivillä on date, number, summary', ['date', 'number', 'summary'].every((k) => adv.document.tracking.revision_history[0][k]));
check('profiili vaatii product_tree', Boolean(adv.product_tree));
check('profiili vaatii vulnerabilities', Array.isArray(adv.vulnerabilities) && adv.vulnerabilities.length > 0);
check('CVE-tunnus menee cve-kenttään', adv.vulnerabilities[0].cve === 'CVE-2026-1234', JSON.stringify(adv.vulnerabilities[0]).slice(0, 120));
check('neuvo kantaa tietoisuushetken', JSON.stringify(adv).includes('2026-09-11T08:00:00.000Z'));
check('neuvo nimeää arvion tekijän', JSON.stringify(adv).includes('Ville'));

// Julkaisijaa ei keksitä.
check('ilman namespacea ei synny neuvoa', run('csaf', '--id', id, '--publisher', 'Acme Oy').code === 2);
r = run('csaf', '--id', id, '--publisher', 'Acme Oy', '--namespace', 'acme.example');
check('namespace on oltava URL', r.code === 2 && /URL/.test(r.out), r.out.slice(0, 120));

// Ei-CVE-tunniste ei saa mennä cve-kenttään.
r = run('aware', '--product', 'Acme', '--vuln', 'ACME-2026-9', '--source', 'https://example.invalid/x', '--decided-by', 'Ville', '--aware', '2026-09-11T08:00:00Z');
const vid = (/KIRJATTU (\S+)/.exec(r.out) ?? [])[1];
const adv2 = JSON.parse(run('csaf', '--id', vid, '--publisher', 'Acme Oy', '--namespace', 'https://acme.example').out);
check('vendor-tunniste menee ids-kenttään', adv2.vulnerabilities[0].cve === undefined && Array.isArray(adv2.vulnerabilities[0].ids), JSON.stringify(adv2.vulnerabilities[0]).slice(0, 140));

rmSync(TMP, { recursive: true, force: true });

console.log(`\n${pass} ok, ${fail.length} fail`);
if (fail.length) { console.log('epäonnistui:'); for (const f of fail) console.log(`  - ${f}`); process.exit(1); }
