resource "ociext_nsg" "app" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "nsg-app"

  defined_tags  = { "FinOps.stack" = "networking", "FinOps.environment" = "pre" }
  freeform_tags = { team = "dba" }

  rules = [
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443", description = "Public HTTPS" },
    { direction = "INGRESS", protocol = "tcp", source = "10.0.1.0/24", ports = "22", description = "SSH from bastion" },
    { direction = "INGRESS", protocol = "icmp", source = "10.0.0.0/8", icmp_type = 3, icmp_code = 4 },
    { direction = "EGRESS", protocol = "all", destination = "all-fra-services-in-oracle-services-network" },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]
}

# Rules that point to an NSG (another one or this one) go in ociext_nsg_peer_rules.

# Rules usually come from a variable or a YAML file; their order does not matter.
resource "ociext_nsg" "db" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "nsg-db"

  rules = [
    for r in yamldecode(file("${path.module}/nsg-db-rules.yaml")) : {
      direction   = "INGRESS"
      protocol    = "tcp"
      source      = r.source
      ports       = r.ports
      description = try(r.description, null)
    }
  ]
}
