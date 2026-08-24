#!/usr/bin/env node
'use strict';

/**
 * csaf.mjs — CSAF 2.0 -neuvon tuottaminen kirjatusta tapahtumasta.
 *
 * MIKSI: CSAF (Common Security Advisory Framework) on koneluettava muoto jolla
 * valmistaja julkaisee haavoittuvuusneuvon. Kilpailija myy "CSAF 2.0 advisory
 * export" osana 99 EUR/kk pakettia, ja se on aito pariteettivaatimus: ilman
 * sitä CRA-polku katkeaa siihen kohtaan jossa neuvo pitäisi julkaista.
 *
 * RAKENNE on verifioitu OASIS CSAF 2.0 -spesifikaatiosta, ei muistista:
 *   /document              5 pakollista: category, csaf_version, publisher,
 *                          title, tracking
 *   /document/tracking     6 pakollista: current_release_date, id,
 *                          initial_release_date, revision_history, status,
 *                          version
 *   revision_history       jokaisella: date, number, summary
 *   csaf_security_advisory -profiili vaatii lisäksi product_tree ja
 *                          vulnerabilities
 *
 * FAIL CLOSED: julkaisijan nimeä ja namespacea EI keksitä. Jos ne puuttuvat,
 * tiedostoa ei synny. Väärä namespace CSAF-neuvossa on pahempi kuin puuttuva
 * neuvo, koska se väittää alkuperää jota ei ole.
 *
 * Käyttö moduulina:  import { buildAdvisory, validateAdvisory } from './csaf.mjs'
 */

/** CSAF 2.0 pakolliset kentät, verifioitu spesifikaatiosta. */
export const REQUIRED_DOCUMENT = ['category', 'csaf_version', 'publisher', 'title', 'tracking'];
export const REQUIRED_TRACKING = ['current_release_date', 'id', 'initial_release_date', 'revision_history', 'status', 'version'];
const VALID_STATUS = ['draft', 'final', 'interim'];

/**
 * Rakentaa csaf_security_advisory -profiilin mukaisen neuvon.
 * Kaikki aikaleimat tulevat kutsujalta: tämä funktio on puhdas, jotta sama
 * tapahtuma tuottaa aina saman neuvon eikä testi ole kellon armoilla.
 */
export function buildAdvisory({ event, publisherName, publisherNamespace, status = 'draft', version = '1.0.0', releaseDate, revisionSummary = 'Initial version.' }) {
  const missing = [];
  if (!event) missing.push('event');
  if (!publisherName) missing.push('publisherName');
  if (!publisherNamespace) missing.push('publisherNamespace');
  if (missing.length) throw new Error(`puuttuu: ${missing.join(', ')} — julkaisijaa ei keksitä`);
  if (!VALID_STATUS.includes(status)) throw new Error(`tuntematon status: ${status}`);
  if (!/^https?:\/\//.test(publisherNamespace)) throw new Error(`publisherNamespace on oltava URL: ${publisherNamespace}`);

  const date = releaseDate ?? event.aware_at;
  const productId = `PROD-${(event.product ?? 'unknown').replace(/[^A-Za-z0-9]+/g, '-').toUpperCase()}`;

  return {
    document: {
      category: 'csaf_security_advisory',
      csaf_version: '2.0',
      publisher: {
        category: 'vendor',
        name: publisherName,
        namespace: publisherNamespace,
      },
      title: `${event.product}: ${event.vuln}`,
      tracking: {
        current_release_date: date,
        id: `CRA24-${String(event.id).slice(0, 8).toUpperCase()}`,
        initial_release_date: date,
        revision_history: [{ date, number: '1', summary: revisionSummary }],
        status,
        version,
      },
      notes: [
        {
          category: 'general',
          title: 'CRA Article 14 awareness',
          // Tämä on se tieto jota kilpailijan vuo ei kanna neuvoon asti:
          // milloin tietoisuus alkoi ja kuka arvion teki.
          text: `Awareness established ${event.aware_at} by ${event.decided_by}. Source: ${event.source}.`,
        },
      ],
    },
    product_tree: {
      full_product_names: [{ product_id: productId, name: event.product }],
    },
    vulnerabilities: [
      {
        ...(/^CVE-\d{4}-\d{4,}$/.test(event.vuln ?? '') ? { cve: event.vuln } : { ids: [{ system_name: 'vendor', text: event.vuln }] }),
        notes: [{ category: 'description', title: 'Status', text: event.actively_exploited ? 'Actively exploited.' : 'Exploitation status not confirmed.' }],
        product_status: { known_affected: [productId] },
      },
    ],
  };
}

/** Tarkistaa pakolliset kentät. Palauttaa listan puutteista, ei heitä. */
export function validateAdvisory(doc) {
  const errors = [];
  if (!doc || typeof doc !== 'object') return { ok: false, errors: ['ei ole olio'] };
  const d = doc.document;
  if (!d) errors.push('/document puuttuu');
  else {
    for (const k of REQUIRED_DOCUMENT) if (d[k] === undefined) errors.push(`/document/${k} puuttuu`);
    if (d.csaf_version !== '2.0') errors.push(`/document/csaf_version on '${d.csaf_version}', odotettu '2.0'`);
    const p = d.publisher ?? {};
    for (const k of ['category', 'name', 'namespace']) if (!p[k]) errors.push(`/document/publisher/${k} puuttuu`);
    const t = d.tracking ?? {};
    for (const k of REQUIRED_TRACKING) if (t[k] === undefined) errors.push(`/document/tracking/${k} puuttuu`);
    const rh = t.revision_history;
    if (!Array.isArray(rh) || !rh.length) errors.push('/document/tracking/revision_history on tyhjä');
    else for (const [i, r] of rh.entries()) {
      for (const k of ['date', 'number', 'summary']) if (!r[k]) errors.push(`/document/tracking/revision_history[${i}]/${k} puuttuu`);
    }
    if (t.status && !VALID_STATUS.includes(t.status)) errors.push(`/document/tracking/status on '${t.status}'`);
  }
  // csaf_security_advisory -profiili
  if (doc.document?.category === 'csaf_security_advisory') {
    if (!doc.product_tree) errors.push('/product_tree puuttuu (csaf_security_advisory vaatii)');
    if (!Array.isArray(doc.vulnerabilities) || !doc.vulnerabilities.length) errors.push('/vulnerabilities puuttuu (csaf_security_advisory vaatii)');
  }
  return { ok: errors.length === 0, errors };
}
