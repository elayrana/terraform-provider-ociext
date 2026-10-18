# Two NSGs that reference each other. With the rules inside ociext_nsg this
# would be a dependency cycle; here Terraform creates both NSGs first and then
# their peer rules.
resource "ociext_nsg" "app" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "nsg-app"

  rules = [
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443" },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]
}

resource "ociext_nsg" "db" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "nsg-db"
}

resource "ociext_nsg_peer_rules" "app" {
  nsg_id = ociext_nsg.app.id

  rules = [
    # Traffic between the instances of the app NSG itself.
    { direction = "INGRESS", protocol = "all", source = ociext_nsg.app.id },
    { direction = "EGRESS", protocol = "tcp", destination = ociext_nsg.db.id, ports = "5432" },
  ]
}

resource "ociext_nsg_peer_rules" "db" {
  nsg_id = ociext_nsg.db.id

  rules = [
    { direction = "INGRESS", protocol = "tcp", source = ociext_nsg.app.id, ports = "5432", description = "PostgreSQL from app" },
  ]
}
