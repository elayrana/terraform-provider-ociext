# Test run: every rule type against OCI

- **Date:** 2026-10-18
- **Tenancy:** personal Free Tier, region `eu-madrid-1`, compartment `Test-nsg`
- **Provider:** local build with `dev_overrides`
- **Terraform:** 1.14
- **Config:** `~/personal/ociext-sandbox-peers/main.tf`
  - `ociext_nsg.app` (19 rules), `ociext_nsg.db` (2 rules);
  - `ociext_nsg_peer_rules.app` (6 rules), `ociext_nsg_peer_rules.db` (3 rules);
  - 30 rules in total.

Times are the wall-clock time of the whole `terraform` command, from a single run.

## Protocols accepted by OCI

Each value was tried with one INGRESS rule from `10.0.0.0/8` on a throwaway NSG, using the OCI CLI directly. The NSG was deleted afterwards.

| Protocol value | OCI | Error |
|----------------|-----|-------|
| `all` | accepted | |
| `0` | **rejected** | `The requested protocol '0' is invalid for this request type.` |
| `1` to `254` | accepted (all 254) | |
| `255` | **rejected** | `The requested protocol '255' is invalid for this request type.` |

The provider now rejects `0` and `255` at plan time and accepts these names:

| Name | IANA number | Ports | ICMP type/code |
|------|-------------|-------|----------------|
| `all` | all | no | no |
| `icmp` | 1 | no | yes |
| `ipip` | 4 | no | no |
| `tcp` | 6 | yes | no |
| `udp` | 17 | yes | no |
| `gre` | 47 | no | no |
| `esp` | 50 | no | no |
| `ah` | 51 | no | no |
| `icmpv6` | 58 | no | yes |
| `ospf` | 89 | no | no |
| `vrrp` | 112 | no | no |
| `sctp` | 132 | no | no |

Any other protocol is written as its number (`1`–`254`). Names are case-insensitive, and a name and its number are the same rule (same key).

## Rules applied

All of them were created, read back with no drift and destroyed. "OCI" shows what `ListNetworkSecurityGroupSecurityRules` returned.

| Resource | Direction | Protocol | Source / destination | Options | OCI |
|----------|-----------|----------|----------------------|---------|-----|
| nsg.app | INGRESS | `tcp` | `0.0.0.0/0` | ports `443` | p=6 dst 443-443 |
| nsg.app | INGRESS | `tcp` | `10.0.0.0/16` | ports `8000-8100`, source_ports `1024-65535` | p=6 dst 8000-8100 src 1024-65535 |
| nsg.app | INGRESS | `6` | `10.0.5.0/24` | ports `22-22` | p=6 dst 22-22 |
| nsg.app | EGRESS | `tcp` | `0.0.0.0/0` | ports `443` | p=6 dst 443-443 |
| nsg.app | INGRESS | `udp` | `10.0.0.0/16` | ports `53` | p=17 dst 53-53 |
| nsg.app | INGRESS | `udp` | `10.0.0.0/16` | source_ports `123` only | p=17 src 123-123 |
| nsg.app | EGRESS | `17` | `0.0.0.0/0` | ports `123` | p=17 dst 123-123 |
| nsg.app | INGRESS | `icmp` | `0.0.0.0/0` | type 3, code 4 | p=1 icmp 3/4 |
| nsg.app | INGRESS | `icmp` | `10.0.0.0/8` | type 8, no code | p=1 icmp 8/any |
| nsg.app | INGRESS | `icmp` | `10.1.0.0/16` | all ICMP | p=1 |
| nsg.app | EGRESS | `icmp` | `0.0.0.0/0` | all ICMP | p=1 |
| nsg.app | INGRESS | `4` → `ipip` | `10.0.0.0/8` | | p=4 |
| nsg.app | INGRESS | `47` → `gre` | `10.0.0.0/8` | | p=47 |
| nsg.app | INGRESS | `50` → `esp` | `10.0.0.0/8` | | p=50 |
| nsg.app | INGRESS | `51` → `ah` | `10.0.0.0/8` | | p=51 |
| nsg.app | INGRESS | `132` → `sctp` | `10.0.0.0/8` | | p=132 |
| nsg.app | INGRESS | `all` | `10.2.0.0/16` | stateless | p=all stateless |
| nsg.app | EGRESS | `all` | `all-mad-services-in-oracle-services-network` | service | p=all SERVICE_CIDR_BLOCK |
| nsg.app | EGRESS | `all` | `0.0.0.0/0` | | p=all |
| nsg.db | EGRESS | `all` | `all-mad-services-in-oracle-services-network` | service | p=all SERVICE_CIDR_BLOCK |
| nsg.db | INGRESS | `tcp` | `10.0.9.0/24` | ports `5432` | p=6 dst 5432-5432 |
| peer_rules.app | INGRESS | `all` | app (itself) | | p=all NSG |
| peer_rules.app | EGRESS | `tcp` | db | ports `5432` | p=6 NSG |
| peer_rules.app | EGRESS | `udp` | db | ports `5000-5010` | p=17 NSG |
| peer_rules.app | INGRESS | `icmp` | db | type 0 | p=1 icmp 0/any NSG |
| peer_rules.app | EGRESS | `47` → `gre` | db | | p=47 NSG |
| peer_rules.app | INGRESS | `tcp` | db | source_ports `5432`, stateless | p=6 src 5432-5432 stateless NSG |
| peer_rules.db | INGRESS | `tcp` | app | ports `5432` | p=6 NSG |
| peer_rules.db | INGRESS | `udp` | app | ports `5000-5010` | p=17 NSG |
| peer_rules.db | EGRESS | `all` | app | | p=all NSG |

## Steps

| # | Step | Expected | Result | Time |
|---|------|----------|--------|------|
| 1 | `apply` create, 4 resources and 30 rules | all rules created as configured | OK (checked rule by rule in OCI) | 1.2 s |
| 2 | `plan` | No changes (`6`, `17`, `22-22` keep their spelling) | OK | 0.6 s |
| 3 | Drift: delete by hand the UDP source-port-only rule and the ICMP type-only rule, add a GRE rule from `172.16.0.0/12`, then `plan` | exactly those 3 rules in the diff | OK: `+2 −1`, "17 unchanged elements hidden" | 0.8 s |
| 4 | `apply` to fix the drift | 1 change | OK | 1.3 s |
| 5 | `plan` | No changes | OK | 0.6 s |
| 6 | `plan` with the new build (protocol names), same config and state | No changes | OK | 0.9 s |
| 7 | Change `4/47/50/51/132` to `ipip/gre/esp/ah/sctp` (6 rules), then `plan` | 6 rules shown as `−`/`+` | OK (see note 1) | 0.8 s |
| 8 | `apply` names | no rule recreated in OCI | OK: `time-created` of the 6 rules unchanged (13:16, before the apply) | 1.3 s |
| 9 | `plan` | No changes | OK | 0.8 s |
| 10 | `protocol = "0"`, then `plan` | rejected at plan time | OK: `protocol "0" must be all, a protocol name (...) or a number between 1 and 254` | 0.1 s |
| 11 | `destroy` | peer rules first, then NSGs; nothing left | OK | 4.6 s |

## Notes

1. **Switching a rule between number and name (`47` ↔ `gre`) shows up in the plan, but the apply does nothing in OCI.** Terraform compares set elements as written, so the plan shows the old spelling removed and the new one added. The provider compares rules by key, sees no change and makes no API call: it only updates the state. The same happens with `443` ↔ `443-443`.
2. **IPv6 was not tested.** OCI rejects IPv6 CIDRs when the VCN has no IPv6 prefix: `VCN ... is not applicable for IPv6 security rule CIDR ::/0.` Testing `icmpv6` and IPv6 CIDRs needs IPv6 enabled on the VCN. The provider already accepts and normalizes IPv6 CIDRs (unit test `TestTargetTypes`).
3. Plans in this run took 0.6–1.1 s, against ~5 s in the morning run (`2026-10-18-nsg-peer-rules.md`). Those plans had 116 rules, these have 30. In both runs, a plan of a resource does one `GetNetworkSecurityGroup` and one paginated list.
