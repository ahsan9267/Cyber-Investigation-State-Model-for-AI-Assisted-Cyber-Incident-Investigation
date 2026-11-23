# Step 3: alert association

Step 3 compares an incoming normalized record with a supplied case snapshot and returns a routing recommendation. It does not create cases or execute an investigation. The persistent manager in Step 4 applies the recommendation transactionally.

This publication uses the installed source snapshot exported on 23 November 2026. The operational association policy in `src/spine/association.py` is `alert_association/1.6.0`. The prototype modules retain their separate policy identities and are not interchangeable with the production router.

## Components

| File | Responsibility |
| --- | --- |
| `src/spine/association.py` | Candidate comparisons, bounded routing decisions and explanations |
| `src/spine/association_profiles.py` | Contextual Windows login, service and DNS episode relations |
| `src/spine/occurrences.py` | Explicit representation/occurrence references and conservative fallback |
| `src/spine/evidence.py` | Derived evidence annotations with retained raw records |
| `src/spine/ait_dataset.py` | Offline adapter for the supported AIT dataset export |
| `src/spine/association_prototype.py` | Earlier isolated association prototype |
| `src/spine/association_v2.py` | Separate candidate/session-conflict prototype |

## Inputs and scope

Records come from the Step 2 envelope and preserve their source identity and raw text. The caller supplies the snapshot; the router distinguishes incomplete input, candidate support, ambiguity, repeated representations and the disposition of existing cases. A relation is contextual support, not proof of incident causality or malicious intent.

The operational source contains a 3600-second gap bound and a 7200-second case-span bound, plus narrower episode limits. Those numbers are local engineering parameters unless a reviewed traceability document establishes a different basis. Host, account, process and network identifiers must retain their recorded scope; an activity marker alone is not an association method.

The AIT adapter expects its documented external dataset inputs. The dataset itself, local capture files and runtime evidence are not part of this publication.

## Research status

The exported operational code does not supply a completed paper-to-rule traceability gate. Preserve the existing policy identity when presenting it. Do not attribute the whole router or its thresholds to HOLMES or another paper merely because the paper discusses related dependencies. Research alignment, any policy change, and independent evaluation require their own reviewed work.

## Using the publication

Both contributors' branches must be integrated before treating this as the completed source publication. Dependencies are provided by the existing Step 2 source and the Step 4 publication. Runtime tests were not rerun while preparing the upload packs.

See [verification](verification.md) and the [persistent manager](../step-04-persistent-manager/README.md).
