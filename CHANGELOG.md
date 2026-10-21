## 0.2.1 (October 21, 2026)

BUG FIXES:

* `ociext_nsg` and `ociext_nsg_peer_rules`: removing the description of an existing rule failed with `InvalidParameter`, because OCI rejects an empty description. The update now leaves it out, which clears it.

## 0.2.0 (October 18, 2026)

FEATURES:

* `ociext_nsg`: new `defined_tags` attribute, written as `Namespace.key`.
* provider: new `ignore_defined_tags` attribute, the same as in the `oracle/oci` provider: the listed defined tags (e.g. `Oracle-Tags.CreatedBy`) are not read into state and are kept on update.

ENHANCEMENTS:

* `ociext_nsg` and `ociext_nsg_peer_rules`: creating or importing with an OCID of another region than the provider configuration fails with an error that names both regions, instead of a 404 from OCI.

BREAKING CHANGES:

* `ociext_nsg`: `freeform_tags` is now Optional and Computed, like the tags of the `oracle/oci` provider. Without the attribute the tags are not managed: they are read from OCI and left as they are, so importing an NSG with tags no longer plans to remove them. To remove all the tags, set `freeform_tags = {}`.

## 0.1.0 (October 18, 2026)

FEATURES:

* **New Resource:** `ociext_nsg`: network security group with its CIDR and service rules managed as one set. Rules are matched by content, so adding or removing one rule only changes that rule, and changes are applied in batches of 25.
* **New Resource:** `ociext_nsg_peer_rules`: the rules of an NSG whose source or destination is an NSG, including the NSG itself. NSGs in the same configuration can reference each other without a dependency cycle.
