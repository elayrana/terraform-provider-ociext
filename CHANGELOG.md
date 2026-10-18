## 0.1.0 (October 18, 2026)

FEATURES:

* **New Resource:** `ociext_nsg`: network security group with its CIDR and service rules managed as one set. Rules are matched by content, so adding or removing one rule only changes that rule, and changes are applied in batches of 25.
* **New Resource:** `ociext_nsg_peer_rules`: the rules of an NSG whose source or destination is an NSG, including the NSG itself. NSGs in the same configuration can reference each other without a dependency cycle.
