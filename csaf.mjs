#!/usr/bin/env node
'use strict';

/**
 * csaf.mjs — produce a CSAF 2.0 advisory from a recorded event.
 *
 * WHY: CSAF (Common Security Advisory Framework) is the machine-readable
 * form in which a manufacturer publishes a vulnerability advisory.
 *
 * STRUCTURE verified from the OASIS CSAF 2.0 specification, not from memory:
 *   /document              5 required: category, csaf_version, publisher,
 *                          title, tracking
 *   /document/tracking     6 required: current_release_date, id,
 *                          initial_release_date, revision_history, status,
 *                          version
 *   revision_history       each: date, number, summary
 *   csaf_security_advisory profile also requires product_tree and
 *                          vulnerabilities
 *
 * FAIL CLOSED: publisher name and namespace are NOT invented. If they are
 * missing, no file is produced. A wrong namespace on a CSAF advisory is
 * worse than a missing advisory, because it claims an origin that is not there.
 *
 * As a module:  import { buildAdvisory, validateAdvisory } from './csaf.mjs'
 */

/** CSAF 2.0 required fields, verified against the specification. */
export const REQUIRED_DOCUMENT = ['category', 'csaf_version', 'publisher', 'title', 'tracking'];
export const REQUIRED_TRACKING = ['current_release_date', 'id', 'initial_release_date', 'revision_history', 'status', 'version'];
const VALID_STATUS = ['draft', 'final', 'interim'];

/**
 * Builds an advisory matching the csaf_security_advisory profile.
 * All timestamps come from the caller: this function is pure so the same
 * event always produces the same advisory and tests are not clock-dependent.
 */
export function buildAdvisory({ event, publisherName, publisherNamespace, status = 'draft', version = '1.0.0', releaseDate, revisionSummary = 'Initial version.' }) {
  const missing = [];
  if (!event) missing.push('event');
  if (!publisherName) missing.push('publisherName');
  if (!publisherNamespace) missing.push('publisherNamespace');
  if (missing.length) throw new Error(`missing: ${missing.join(', ')} — publisher is not invented`);
  if (!VALID_STATUS.includes(status)) throw new Error(`unknown status: ${status}`);
  if (!/^https?:\/\//.test(publisherNamespace)) throw new Error(`publisherNamespace must be a URL: ${publisherNamespace}`);

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
          // The fact most reporting flows never carry into the advisory:
          // when awareness began, and who made the call.
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

/** Checks required fields. Returns a list of gaps; does not throw. */
export function validateAdvisory(doc) {
  const errors = [];
  if (!doc || typeof doc !== 'object') return { ok: false, errors: ['not an object'] };
  const d = doc.document;
  if (!d) errors.push('/document missing');
  else {
    for (const k of REQUIRED_DOCUMENT) if (d[k] === undefined) errors.push(`/document/${k} missing`);
    if (d.csaf_version !== '2.0') errors.push(`/document/csaf_version is '${d.csaf_version}', expected '2.0'`);
    const p = d.publisher ?? {};
    for (const k of ['category', 'name', 'namespace']) if (!p[k]) errors.push(`/document/publisher/${k} missing`);
    const t = d.tracking ?? {};
    for (const k of REQUIRED_TRACKING) if (t[k] === undefined) errors.push(`/document/tracking/${k} missing`);
    const rh = t.revision_history;
    if (!Array.isArray(rh) || !rh.length) errors.push('/document/tracking/revision_history is empty');
    else for (const [i, r] of rh.entries()) {
      for (const k of ['date', 'number', 'summary']) if (!r[k]) errors.push(`/document/tracking/revision_history[${i}]/${k} missing`);
    }
    if (t.status && !VALID_STATUS.includes(t.status)) errors.push(`/document/tracking/status is '${t.status}'`);
  }
  // csaf_security_advisory profile
  if (doc.document?.category === 'csaf_security_advisory') {
    if (!doc.product_tree) errors.push('/product_tree missing (required by csaf_security_advisory)');
    if (!Array.isArray(doc.vulnerabilities) || !doc.vulnerabilities.length) errors.push('/vulnerabilities missing (required by csaf_security_advisory)');
  }
  return { ok: errors.length === 0, errors };
}
