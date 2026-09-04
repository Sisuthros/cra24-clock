#!/usr/bin/env node
'use strict';

/**
 * cra-clock.mjs — CRA 14 artiklan kello ja todisteketju.
 *
 * MIKÄ ONGELMA: 11.9.2026 alkaen EU-valmistajan on ilmoitettava aktiivisesti
 * hyväksikäytetystä haavoittuvuudesta ENISAlle ja koordinoivalle CSIRTille
 * 24 tunnissa, annettava tarkempi arvio 72 tunnissa ja loppuraportti 14
 * vuorokaudessa. Velvoite koskee myös tuotteita jotka on jo myyty.
 *
 * Kello alkaa TIETOISUUDESTA, ei varmistuksesta. Valvoja kysyy jälkikäteen
 * kolme asiaa, ja kaikki kolme ovat todistuskysymyksiä:
 *   1. Milloin tarkalleen tulitte tietoisiksi?
 *   2. Kuka päätti että kyseessä on aktiivinen hyväksikäyttö?
 *   3. Lähtikö ilmoitus tasan kerran?
 *
 * ENISAn Single Reporting Platformilla ei ole rajapintaa, joten lähetys ja
 * uudelleenyritys ovat ihmisen käsissä. Silloin tuplailmoitus on todellinen
 * riski, ja niin on myös aikaleima jota ei voi puolustaa.
 *
 * MITÄ TÄMÄ TEKEE: kirjaa tietoisuushetken, laskee kolme määräaikaa, tuottaa
 * esitäytetyt luonnokset, ja pitää hash-ketjutettua lokia jota ei voi muokata
 * jälkikäteen huomaamatta. Lähetys merkitään TASAN KERRAN vaiheessa.
 *
 * MITÄ TÄMÄ EI TEE: ei lähetä mitään viranomaiselle, ei päätä puolestasi onko
 * haavoittuvuus aktiivisesti hyväksikäytetty, ei ole oikeudellinen neuvo eikä
 * skannaa koodia. Kaikki data pysyy omalla koneella.
 *
 * Käyttö:
 *   node cra-clock.mjs deadlines --aware 2026-09-11T08:00:00Z
 *   node cra-clock.mjs aware --product "Acme FW" --vuln CVE-2026-1234 --source <url> --decided-by "nimi"
 *   node cra-clock.mjs draft  --id <id> --stage early|detailed|final
 *   node cra-clock.mjs submitted --id <id> --stage early --ref SRP-123
 *   node cra-clock.mjs status [--json]
 *   node cra-clock.mjs verify
 *
 * Exit: 0 = ok · 1 = ketju rikki tai tuplalähetys estetty · 2 = käyttövirhe
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
 * CRA 14 art. kaskadi. Puhdas funktio: sama syöte, sama tulos, aina.
 *
 * Kaksi ensimmäistä määräaikaa lasketaan tietoisuudesta. Loppuraportti EI:
 * asetus sitoo sen siihen hetkeen jolloin korjaava toimi on saatavilla.
 * Niin kauan kuin sitä hetkeä ei tiedetä, määräaikaa ei ole olemassa, ja
 * työkalu sanoo sen sellaisenaan sen sijaan että keksisi päivämäärän.
 *
 * Korjattu 2026-09-04: aiemmin `final.due` oli tietoisuus + 336 h. Se antoi
 * aina liian aikaisen määräajan silloin kun korjaus valmistui myöhemmin kuin
 * 14 vrk tietoisuudesta, ja se on juuri se virhe jonka estämiseksi tämä
 * työkalu on olemassa.
 */
export function deadlines(awareIso, remediationIso = null) {
  const t = new Date(awareIso).getTime();
  if (Number.isNaN(t)) throw new Error(`aikaleima ei jäsenny: ${awareIso}`);
  const at = (base, h) => new Date(base + h * 3600_000).toISOString();

  let r = null;
  if (remediationIso != null && remediationIso !== '') {
    r = new Date(remediationIso).getTime();
    if (Number.isNaN(r)) throw new Error(`korjauksen aikaleima ei jäsenny: ${remediationIso}`);
    if (r < t) throw new Error('korjaus ei voi olla saatavilla ennen kuin tietoisuus alkoi');
  }

  return {
    aware_at: new Date(t).toISOString(),
    remediation_available_at: r === null ? null : new Date(r).toISOString(),
    early_warning: { stage: 'early', due: at(t, 24), hours: 24, basis: 'aware_at', pending: false, what: 'Ennakkovaroitus ENISAlle ja koordinoivalle CSIRTille' },
    detailed: { stage: 'detailed', due: at(t, 72), hours: 72, basis: 'aware_at', pending: false, what: 'Tarkempi arvio, korjaavat toimet' },
    final: r === null
      ? {
          stage: 'final', due: null, hours: 336, basis: 'remediation_available_at', pending: true,
          earliest_possible: at(t, 336),
          what: 'Loppuraportti. Määräaika alkaa vasta kun korjaava toimi on saatavilla, joten sitä ei voi vielä laskea.',
        }
      : {
          stage: 'final', due: at(r, 336), hours: 336, basis: 'remediation_available_at', pending: false,
          earliest_possible: at(t, 336),
          what: 'Loppuraportti korjaavan toimen tultua saataville',
        },
  };
}

/** Näytettävä määräaika, kun sitä ei välttämättä ole. Ei koskaan keksittyä päivää. */
export function dueText(stageObj) {
  if (stageObj.due) return stageObj.due;
  return `ei vielä laskettavissa (aikaisintaan ${stageObj.earliest_possible}, alkaa korjauksen saatavillaolosta)`;
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
 * Kirjoita hash-ketjutettu rivi ja lue se takaisin. Jokainen rivi sitoutuu
 * edeltäjäänsä, joten yhden rivin muuttaminen jälkikäteen katkaisee ketjun ja
 * `verify` näkee sen. Tämä on se osa jota lomakkeen täyttö ei anna.
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
  if (!back) { console.error('🛑 cra-clock: rivi ei näy takaisinluvussa — älä väitä tätä kirjatuksi.'); process.exit(1); }
  return full;
}

export function verifyChain(rows) {
  const problems = [];
  let prev = ''.padEnd(64, '0');
  for (const [i, r] of rows.entries()) {
    if (r.__broken) { problems.push(`rivi ${i + 1}: ei jäsenny JSONiksi`); continue; }
    if (r.prev_sha256 !== prev) problems.push(`rivi ${i + 1}: prev_sha256 ei vastaa edellistä riviä`);
    const { entry_sha256, ...body } = r;
    if (sha256(JSON.stringify(body)) !== entry_sha256) problems.push(`rivi ${i + 1}: sisältö muuttunut kirjaamisen jälkeen`);
    prev = entry_sha256;
  }
  return { ok: problems.length === 0, problems, count: rows.length };
}

const STAGES = ['early', 'detailed', 'final'];

/** Esitäytetty luonnos. Pakolliset kentät joita ostaja ei voi unohtaa. */
function draftFor(ev, stage) {
  const rem = remediationFor(ev.id);
  const d = deadlines(ev.aware_at, rem);
  const st = d[stage === 'early' ? 'early_warning' : stage];
  const lines = [
    `CRA 14 art. — ${stage === 'early' ? 'ENNAKKOVAROITUS (24 h)' : stage === 'detailed' ? 'TARKEMPI ARVIO (72 h)' : 'LOPPURAPORTTI (14 vrk korjauksesta)'}`,
    ``,
    `Tuote: ${ev.product}`,
    `Haavoittuvuus: ${ev.vuln}`,
    `Tietoisuus alkoi: ${ev.aware_at}`,
    `Määräaika: ${dueText(st)}`,
    `Arvion teki: ${ev.decided_by}`,
    `Lähde: ${ev.source}`,
    ``,
    `Aktiivisesti hyväksikäytetty: ${ev.actively_exploited ? 'KYLLÄ' : '<<TÄYTÄ: kyllä/ei ja perustelu>>'}`,
    `Jäsenvaltiot joissa tuote on saatavilla: <<TÄYTÄ>>`,
  ];
  if (stage !== 'early') lines.push(`Korjaavat tai lieventävät toimet: <<TÄYTÄ>>`, `Vaikutusarvio: <<TÄYTÄ>>`);
  if (stage === 'final') {
    lines.push(
      rem
        ? `Korjaus saatavilla alkaen: ${rem}  (kirjattu todisteketjuun)`
        : `Korjaus saatavilla alkaen: <<TÄYTÄ — kirjaa se komennolla: cra-clock.mjs remediation --id ${ev.id.slice(0, 8)} --at <ISO>>>`,
      `Jakelutapa käyttäjille: <<TÄYTÄ>>`
    );
  }
  lines.push(
    ``,
    `Tapahtumatunnus: ${ev.id}`,
    `Todisteketju: ${path.relative(process.cwd(), LOG)}`,
    ``,
    `Tämä on luonnos. Se ei ole oikeudellinen neuvo, eikä tämä työkalu lähetä`,
    `mitään viranomaiselle. Lähetys tehdään ENISAn Single Reporting Platformilla.`
  );
  return lines.join('\n');
}

const events = () => readLog().filter((r) => r.type === 'aware');
const findEvent = (id) => events().find((e) => e.id === id || e.id.startsWith(id));

/** Viimeisin kirjattu korjauksen saatavillaolo, tai null. Tämä ratkaisee loppuraportin määräajan. */
function remediationFor(eventId) {
  const rows = readLog().filter((r) => r.type === 'remediation' && r.event_id === eventId);
  return rows.length ? rows[rows.length - 1].available_at : null;
}

// --------------------------------------------------------------------------

if (cmd === 'deadlines') {
  const aware = flag('aware');
  if (!aware) { console.error('Käyttö: deadlines --aware <ISO-aikaleima>'); process.exit(2); }
  let d;
  try { d = deadlines(aware, flag('remediation')); } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  if (argv.includes('--json')) { console.log(JSON.stringify(d, null, 2)); }
  else {
    console.log(`Tietoisuus alkoi: ${d.aware_at}`);
    if (d.remediation_available_at) console.log(`Korjaus saatavilla: ${d.remediation_available_at}`);
    for (const k of ['early_warning', 'detailed', 'final']) {
      const s = d[k];
      console.log(`  ${String(s.hours).padStart(3)} h  ${dueText(s)}  ${s.what}`);
    }
  }
} else if (cmd === 'aware') {
  const product = flag('product'); const vuln = flag('vuln');
  const source = flag('source'); const decidedBy = flag('decided-by');
  if (!product || !vuln || !source || !decidedBy) {
    console.error('Käyttö: aware --product <nimi> --vuln <tunnus> --source <url> --decided-by <nimi> [--aware <ISO>] [--actively-exploited]');
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
  console.log(`KIRJATTU ${ev.id}`);
  console.log(`  tietoisuus: ${ev.aware_at}   arvion teki: ${ev.decided_by}`);
  for (const k of ['early_warning', 'detailed', 'final']) console.log(`  ${String(d[k].hours).padStart(3)} h  ${dueText(d[k])}`);
  console.log(`  ketjun tiiviste: ${ev.entry_sha256.slice(0, 16)}…`);
} else if (cmd === 'draft') {
  const id = flag('id'); const stage = flag('stage');
  if (!id || !STAGES.includes(stage)) { console.error(`Käyttö: draft --id <id> --stage ${STAGES.join('|')}`); process.exit(2); }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 tapahtumaa ei löydy: ${id}`); process.exit(2); }
  console.log(draftFor(ev, stage));
} else if (cmd === 'submitted') {
  const id = flag('id'); const stage = flag('stage'); const ref = flag('ref');
  if (!id || !STAGES.includes(stage) || !ref) { console.error(`Käyttö: submitted --id <id> --stage ${STAGES.join('|')} --ref <SRP-viite>`); process.exit(2); }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 tapahtumaa ei löydy: ${id}`); process.exit(2); }
  // TASAN KERRAN. Tämä on koko tuotteen lupaus: sama vaihe ei kirjaudu kahdesti,
  // vaikka komento ajettaisiin uudelleen tai skripti käynnistyisi kaatumisen
  // jälkeen. Toinen yritys on virhe eikä hiljainen ohitus.
  const already = readLog().find((r) => r.type === 'submitted' && r.event_id === ev.id && r.stage === stage);
  if (already) {
    console.error(`🛑 ESTETTY: ${stage} on jo merkitty lähetetyksi ${already.at} (viite ${already.ref}).`);
    console.error('   Toinen ilmoitus samasta vaiheesta on juuri se mitä tämä työkalu estää.');
    process.exit(1);
  }
  const row = appendChained({ type: 'submitted', event_id: ev.id, stage, ref });
  console.log(`LÄHETETTY MERKITTY ${stage} — ${ref}`);
  console.log(`  ketjun tiiviste: ${row.entry_sha256.slice(0, 16)}…`);
} else if (cmd === 'remediation') {
  // Loppuraportin määräaika alkaa tästä hetkestä, ei tietoisuudesta.
  const id = flag('id'); const at = flag('at');
  if (!id || !at) { console.error('Käyttö: remediation --id <id> --at <ISO-aikaleima>'); process.exit(2); }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 tapahtumaa ei löydy: ${id}`); process.exit(2); }
  let d;
  try { d = deadlines(ev.aware_at, at); } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  const row = appendChained({ type: 'remediation', event_id: ev.id, available_at: d.remediation_available_at });
  console.log(`KORJAUS SAATAVILLA KIRJATTU ${d.remediation_available_at}`);
  console.log(`  loppuraportin määräaika: ${d.final.due}`);
  console.log(`  ketjun tiiviste: ${row.entry_sha256.slice(0, 16)}…`);
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
      // Ilman määräaikaa ei ole myöhässäoloa. Tuntematon ei ole sama kuin myöhässä.
      if (st.due === null) {
        return { stage: s, due: null, pending: true, earliest_possible: st.earliest_possible, submitted: Boolean(sub), ref: sub?.ref ?? '', overdue: false, hours_left: null };
      }
      const due = new Date(st.due).getTime();
      return { stage: s, due: st.due, pending: false, submitted: Boolean(sub), ref: sub?.ref ?? '', overdue: !sub && now > due, hours_left: Number(((due - now) / 3600_000).toFixed(1)) };
    });
    return { id: ev.id, product: ev.product, vuln: ev.vuln, aware_at: ev.aware_at, remediation_available_at: rem, stages };
  });
  if (argv.includes('--json')) { console.log(JSON.stringify({ events: out, chain: verifyChain(rows) }, null, 2)); }
  else if (!out.length) { console.log('Ei kirjattuja tapahtumia.'); }
  else {
    for (const e of out) {
      console.log(`${e.id.slice(0, 8)}  ${e.product} — ${e.vuln}   tietoisuus ${e.aware_at}`);
      for (const s of e.stages) {
        const mark = s.submitted ? '✅' : s.overdue ? '🔴' : s.pending ? '⏳' : '·';
        const tail = s.submitted
          ? `lähetetty (${s.ref})`
          : s.overdue ? 'MYÖHÄSSÄ'
          : s.pending ? 'odottaa korjauksen saatavillaoloa'
          : `${s.hours_left} h jäljellä`;
        const due = s.due ?? `aikaisintaan ${s.earliest_possible}`;
        console.log(`   ${mark} ${s.stage.padEnd(9)} ${due}  ${tail}`);
      }
    }
    const v = verifyChain(rows);
    console.log(`\ntodisteketju: ${v.ok ? 'ehjä' : 'RIKKI'} (${v.count} riviä)`);
  }
} else if (cmd === 'csaf') {
  // CSAF 2.0 -neuvo kirjatusta tapahtumasta. Julkaisijaa ei keksitä: ilman
  // nimeä ja namespacea tiedostoa ei synny.
  const id = flag('id');
  const name = flag('publisher');
  const ns = flag('namespace');
  if (!id || !name || !ns) {
    console.error('Käyttö: csaf --id <id> --publisher "<nimi>" --namespace https://esimerkki.fi [--status draft|interim|final] [--version 1.0.0]');
    process.exit(2);
  }
  const ev = findEvent(id);
  if (!ev) { console.error(`🛑 tapahtumaa ei löydy: ${id}`); process.exit(2); }
  let doc;
  try {
    doc = buildAdvisory({ event: ev, publisherName: name, publisherNamespace: ns, status: flag('status', 'draft'), version: flag('version', '1.0.0') });
  } catch (e) { console.error(`🛑 ${e.message}`); process.exit(2); }
  const v = validateAdvisory(doc);
  if (!v.ok) {
    // Kelvoton CSAF on pahempi kuin puuttuva: se väittää olevansa neuvo.
    console.error('🛑 tuotettu neuvo ei täytä CSAF 2.0 pakollisia kenttiä:');
    for (const e of v.errors) console.error(`   ✗ ${e}`);
    process.exit(1);
  }
  console.log(JSON.stringify(doc, null, 2));
} else if (cmd === 'verify') {
  const v = verifyChain(readLog());
  if (v.ok) { console.log(`✅ todisteketju ehjä — ${v.count} riviä`); }
  else {
    console.log(`🛑 todisteketju RIKKI — ${v.problems.length} ongelmaa:`);
    for (const p of v.problems) console.log(`  ✗ ${p}`);
    process.exit(1);
  }
} else {
  console.error('Komennot: deadlines | aware | draft | submitted | csaf | status | verify');
  process.exit(2);
}
