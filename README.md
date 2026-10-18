# Terraform Provider OCIExt

Custom Terraform provider with extra resources for [Oracle Cloud Infrastructure (OCI)](https://www.oracle.com/cloud/), starting with Network Security Groups (NSG).

Registry address: `elayrana/ociext`

```hcl
terraform {
  required_providers {
    ociext = {
      source = "elayrana/ociext"
    }
  }
}
```

Built on the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework). It works next to the official [`oracle/oci`](https://registry.terraform.io/providers/oracle/oci/latest) provider: use that one for everything else.

## Why

The official provider manages NSG rules with `oci_core_network_security_group_security_rule`, one resource per rule. With many rules per NSG that means:

- one API call per rule, so creating or changing a large NSG is slow;
- rules added by hand in the console are not detected: no resource owns them, so `plan` stays clean;
- hundreds of resources in the state for a handful of NSGs.

This provider manages the rules of an NSG as one set:

- **`ociext_nsg`** creates the NSG and owns its rules whose source or destination is a CIDR block or an OCI service.
- **`ociext_nsg_peer_rules`** owns the rules of an NSG whose source or destination is an NSG, including the NSG itself.

Each rule is identified by its content (direction, protocol, source or destination, ports, ICMP type and code), not by its position. As a result:

- adding or removing one rule shows exactly that rule in the plan, and only that rule changes in OCI;
- a rule added or deleted outside Terraform shows up as drift and is fixed on the next apply;
- changes go to OCI in batches of 25 rules: adding 115 rules to an NSG takes about 5 seconds.

### Why two resources

Two NSGs in the same configuration often reference each other: the app NSG allows traffic from the database NSG and the other way round. If those rules lived inside `ociext_nsg`, each NSG would depend on the other and Terraform would fail with a dependency cycle. With `ociext_nsg_peer_rules`, Terraform creates the NSGs first and their peer rules after. The split is by target type, so every rule has exactly one place to go and the provider rejects a rule in the wrong resource.

```hcl
resource "ociext_nsg" "app" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "app"
  rules = [
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443" },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]
}

resource "ociext_nsg" "db" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "db"
}

resource "ociext_nsg_peer_rules" "app" {
  nsg_id = ociext_nsg.app.id
  rules = [
    { direction = "EGRESS", protocol = "tcp", destination = ociext_nsg.db.id, ports = "5432" },
    { direction = "INGRESS", protocol = "all", source = ociext_nsg.app.id }, # traffic inside the NSG
  ]
}

resource "ociext_nsg_peer_rules" "db" {
  nsg_id = ociext_nsg.db.id
  rules = [
    { direction = "INGRESS", protocol = "tcp", source = ociext_nsg.app.id, ports = "5432" },
  ]
}
```

See the [resource documentation](docs/resources) for every attribute.

### Things to know

- `ociext_nsg` removes CIDR and service rules that are not in its configuration, and `ociext_nsg_peer_rules` does the same with NSG rules. Do not mix them with `oci_core_network_security_group_security_rule` for the same kind of rule on the same NSG. `ociext_nsg` ignores NSG rules, so peer rules can still come from the official provider.
- Use only one `ociext_nsg_peer_rules` per NSG. Creating it fails if the NSG already has NSG rules that are not in its configuration; import them with `terraform import ociext_nsg_peer_rules.<name> <nsg_ocid>`.
- OCI allows 120 rules per NSG. If your tenancy has a higher limit, set `max_rules_per_nsg` in the provider.
- Protocols are written as `all`, a name (`tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `esp`, ...) or a number from 1 to 254.

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.25 (only to build it)

## Building the Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command:

```shell
go install
```

## Adding Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules).
Please see the Go documentation for the most up to date information about using Go modules.

To add a new dependency `github.com/author/dependency` to your Terraform provider:

```shell
go get github.com/author/dependency
go mod tidy
```

Then commit the changes to `go.mod` and `go.sum`.

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `make generate`.

Unit tests need nothing but Go:

```shell
make test
```

Acceptance tests create, change and destroy real NSGs, and change some of them outside Terraform to check drift. They run on your machine, or on GitHub with the *Acceptance Tests* workflow, which only the repository owner can start by hand. They need an OCI CLI profile and a compartment and VCN for the tests. There is no default profile, so they never run against a tenancy by accident.

```shell
export OCIEXT_TEST_PROFILE=MY_TEST_PROFILE                 # profile of ~/.oci/config
export OCIEXT_TEST_COMPARTMENT_ID=ocid1.compartment.oc1..
export OCIEXT_TEST_VCN_ID=ocid1.vcn.oc1..
export OCIEXT_TEST_REGION=eu-madrid-1                      # optional, defaults to the region of the profile
export OCIEXT_TEST_CONFIG_FILE=~/ci/oci-config              # optional, defaults to ~/.oci/config
export OCIEXT_TEST_DEFINED_TAG=ext-test.env                # optional, a defined tag the tests may set; without it they skip defined tags
make testacc
```

Every NSG they create is named `ociext-acc-...`. NSGs are free, and the tests delete them at the end; if a run is interrupted, delete the leftovers by that prefix.

The workflow reads its OCI credentials from the `acceptance` environment of the repository: secrets `OCI_USER`, `OCI_FINGERPRINT`, `OCI_TENANCY` and `OCI_PRIVATE_KEY`, and variables `OCI_REGION`, `OCIEXT_TEST_COMPARTMENT_ID`, `OCIEXT_TEST_VCN_ID` and `OCIEXT_TEST_DEFINED_TAG`. Use an OCI user that can only manage the network in the test compartment, and use the tag namespace of the test tag.
