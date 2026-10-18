# Test run: `ociext_nsg_peer_rules` against OCI

- **Date:** 2026-10-18
- **Tenancy:** personal Free Tier, region `eu-madrid-1`, compartment `Test-nsg`
- **Provider:** local build with `dev_overrides`, commit `bc2f2f9` plus the uncommitted `ociext_nsg_peer_rules` changes
- **Terraform:** 1.14
- **Config:** `~/personal/ociext-sandbox-peers/main.tf`
  - two `ociext_nsg` (`app`, `db`) that reference each other through `ociext_nsg_peer_rules`;
  - `app` also has a rule that points to itself.

Times are the wall-clock time of the whole `terraform` command, including the refresh. They come from a single run, not an average.

## Results

| # | Step | Rules involved | Expected | Result | Time |
|---|------|----------------|----------|--------|------|
| 1 | `plan`, nothing created yet | 4 resources, 6 rules | 4 to add, no dependency cycle | OK | 0.3 s |
| 2 | `apply` create | 2 NSGs; app: 2 CIDR + 2 peer, db: 1 service + 1 peer | NSGs first, then peer rules | OK | 1.0 s |
| 3 | `plan` after create | 6 | No changes | OK | 0.5 s |
| 4 | `plan` with 110 more peer rules on app | +110 | only the 110 new rules in the diff | OK (110 `+`, 0 `-`) | 2.1 s |
| 5 | `apply` 110 peer rules | app: 114 in total (5 batches of 25) | 1 change | OK | 7.8 s |
| 6 | `plan` with app at 114 rules | 116 | No changes | OK | 5.0 s |
| 7 | Drift: add 1 CIDR and 1 peer rule by hand on app, then `plan` | +2 manual | `ociext_nsg.app` removes the CIDR rule; `peer_rules.app` removes the peer rule | OK: each resource sees only its own rule type | 5.4 s |
| 8 | Drift: also delete `Public HTTPS` (app, CIDR) and `PostgreSQL from app` (db, peer) by hand, then `plan` | −2 managed | both rules added back by their owner | OK: 3 changes (app −1 +1, peer app −1, peer db +1) | 5.5 s |
| 9 | `apply` to fix the drift | 4 rule changes | manual rules removed, deleted rules back | OK: 0 manual rules left, app 114, db 2 | 11.3 s |
| 10 | `plan` after the fix | 116 | No changes | OK | 5.0 s |
| 11 | Guard: `state rm peer_rules.db`, then `apply` (live peer rule identical to the config) | 1 | (see note 1) | Adopted without an error | 5.4 s |
| 12 | Guard: `state rm peer_rules.db`, add a *different* peer rule by hand, then `apply` | 1 foreign | `Create` fails with "NSG already has peer rules" and nothing changes | OK, the error lists the rule key and the import command | 5.3 s |
| 13 | `import ociext_nsg_peer_rules.db <db OCID>` | – | import by NSG OCID | OK | 0.3 s |
| 14 | `plan` after import | 2 | only the foreign rule to remove | OK | 5.3 s |
| 15 | `apply` after import | −1 | foreign rule removed | OK | 5.4 s |
| 16 | NSG reference in `ociext_nsg` to an NSG created in the same apply (unknown at plan time) | 1 | plan passes; apply fails before any rule call | OK: "points to an NSG: those rules go in ociext_nsg_peer_rules", db unchanged | plan 5.2 s, apply 5.6 s |
| 17 | Revert step 16 and `apply` | 1 NSG | extra NSG destroyed | OK | 8.5 s |
| 18 | `plan` | 116 | No changes | OK | 5.3 s |
| 19 | `destroy` | 4 resources, 116 rules | peer rules first, then NSGs; nothing left in OCI | OK | 11.1 s |

Before this run, the same day, a separate sandbox with `ociext_nsg` only gave these numbers:

| Case | Time |
|------|------|
| Add 115 rules to an NSG (5 batches) | ~5 s (apply 7.7 s) |
| `plan` that reads an NSG with 120 rules | 4.9 s |

## Notes

1. **The guard only fires on rules that are not in the configuration.** When a live peer rule matches a configured rule (same key), `Create` adopts it silently (step 11). This is by design: re-creating the resource after a `state rm` with the same config just works. The flip side is that two stacks with *identical* peer rules on the same NSG are not detected. They only fight once their rules differ, and then the guard fires (step 12).
2. Validating a rule in the wrong resource needs the value. When it is unknown at plan time (step 16), the check runs at the start of the apply, before any rule API call. Resources that do not depend on it are still created (the `extra` NSG in step 16).
3. Peer rule changes on app with 112 rules take 3–5 s, about the same as `ociext_nsg` with a similar number of rules: both use one paginated list and batches of 25.
4. A `plan` with existing resources takes ~5 s with 116 rules over 4 resources. Each resource does one `GetNetworkSecurityGroup` and one paginated list.

## Not covered yet

- Acceptance tests (`TF_ACC=1`) for both resources. This run was manual.
- Two stacks with identical peer rules on the same NSG (see note 1).
- A failure in the middle of the batches (some batches applied, a later one rejected).
