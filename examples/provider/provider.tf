# API key from a profile of ~/.oci/config. Only that profile is read:
# missing values are never taken from DEFAULT.
provider "ociext" {
  config_file_profile = "PERSONAL"
  region              = "eu-frankfurt-1"

  # Tags that OCI sets through tag defaults: not read into state, kept on update.
  ignore_defined_tags = ["Oracle-Tags.CreatedBy", "Oracle-Tags.CreatedOn"]
}

# A second region, e.g. for a DR replica: pass it to the resources with provider = ociext.dr.
provider "ociext" {
  alias               = "dr"
  config_file_profile = "PERSONAL"
  region              = "eu-madrid-1"
  ignore_defined_tags = ["Oracle-Tags.CreatedBy", "Oracle-Tags.CreatedOn"]
}
