# CRA 24h Clock

A single-file command-line tool that answers the question a market surveillance authority
asks after an incident: **"when exactly did you become aware?"**

From **11 September 2026**, Article 14 of the EU Cyber Resilience Act (Regulation (EU) 2024/2847)
obliges manufacturers of products with digital elements to report an *actively exploited
vulnerability* with an early warning within **24 hours**, a detailed notification within
**72 hours**, and a final report within **14 days** of a corrective measure becoming available.
The clock starts at **awareness**, not at confirmation, and the obligation covers products
already on the market.

ENISA's Single Reporting Platform is a manual web form with no public API, so submitting
exactly once — and proving you did — is a human problem.

## Run it

Requires Node.js 18+. No install step, no account, no network access.

```
node cra-clock.mjs deadlines --aware 2026-09-11T08:00:00Z
```

```
Tietoisuus alkoi: 2026-09-11T08:00:00.000Z
   24 h  2026-09-12T08:00:00.000Z  Ennakkovaroitus ENISAlle ja koordinoivalle CSIRTille
   72 h  2026-09-14T08:00:00.000Z  Tarkempi arvio, korjaavat toimet
  336 h  2026-09-25T08:00:00.000Z  Loppuraportti korjaavan toimen tultua saataville
```

The CLI currently speaks Finnish; the evidence log and the CSAF 2.0 export are
language-neutral JSON. English CLI output is on the roadmap and is not promised for a date.

## Commands

| Command | What you get |
|---|---|
| `aware` | Records the awareness moment, its source and the person who made the call. Appends to a hash-chained log. |
| `deadlines` | The 24 h / 72 h / 14 d deadlines from any awareness timestamp. Same input, same output, every time. |
| `draft` | Pre-filled notification drafts per stage; every field the regulation expects is either filled or marked `<<FILL>>`. |
| `submitted` | Marks a stage submitted with your SRP reference — *exactly once*. A second attempt exits non-zero instead of being silently absorbed. |
| `csaf` | A CSAF 2.0 advisory with the OASIS-mandatory fields validated. |
| `status` | Every open event: deadlines, what is submitted, what is overdue. |
| `verify` | Re-computes the whole hash chain and names any line edited after the fact — including edits made by us. |

## Verify the claims yourself

```
node cra-clock.test.mjs
```

50 assertions, plain Node, no test framework: deadlines are deterministic, a submission
cannot be recorded twice, tampering with the log is detected, drafts carry the awareness
moment, and CSAF output has every OASIS-mandatory field.

The "your data never leaves your machine" claim is checkable in one grep — it should return
nothing:

```
grep -En "node:(https?|net|dgram|tls)|fetch\(" cra-clock.mjs csaf.mjs
```

## What this is not

It does not submit anything to any authority, does not decide for you whether a
vulnerability is actively exploited, does not scan code or produce an SBOM, and is not
legal advice. It has no SBOM registry, no CVSS scoring, no Article 26 obligations matrix
and no NVD/EUVD feeds. Hosted compliance suites sell all of those; if that is what you
need, buy one of those instead.

## Paid help, if you want it

The tool is free under MIT and always will be. What costs money is a person doing the
setup with you: configuring the evidence log for your product line, running a timed
dry-run of a fictional case with your team, and reviewing your real notification drafts
before you submit them. Details and prices are on the [project page](https://sisuthros.github.io/cra24-clock/).
Business customers only.

## Licence

MIT — see [`LICENSE`](LICENSE).

Built by Ville Myllyniemi (Larnaca, Cyprus) with an AI agent family; a human reads and
publishes everything here.
