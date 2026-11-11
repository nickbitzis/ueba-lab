## Scenario detection

| Id | Scenario | Starts day | Detected | Days to detect | Peak risk | Top reason |
|---|---|---|---|---|---|---|
| S1 | departing bulk download | 60 | yes | 0 | 100 | First access to repo:eng-mobile-jobs; no engineer@eng-data peer accessed it in 30 days |
| S2 | compromised account | 63 | yes | 0 | 94 | Sign-in from new country IS, then mfa reset 25 min later |
| S3 | service account interactive | 59 | yes | 0 | 89 | Service account used for 1 interactive sign-in(s); it normally signs in only with tokens. |
| S4 | credential sharing | 52 | yes | 0 | 87 | Activity from Dublin and Austin 7,447 km apart, 5.8 h apart (1,291 km/h) |
| S5 | contractor after end date | 61 | yes | 0 | 98 | 6 events 1 day(s) after the contract end date |
| S6 | admin mass permission change | 66 | yes | 0 | 59 | 120 privilege changes vs usual 3 (40.0x); it_admin@it peers today median 3 |

## Alert volume

| Configuration | Signals | Cases | Cases per week | Scenarios caught | Benign surprise cases | Other cases | Precision |
|---|---|---|---|---|---|---|---|
| Peers and context | 905 | 6 | 0.68 | 6 / 6 | 0 | 0 | 100% |
| Peers, no context | 897 | 10 | 1.13 | 5 / 6 | 5 | 0 | 50% |
| Context, no peers | 1,878 | 6 | 0.68 | 6 / 6 | 0 | 0 | 100% |
| Neither | 1,870 | 25 | 2.82 | 5 / 6 | 20 | 0 | 20% |

Gate (every scenario within 3 days, at most 1 benign cases): PASSED
