# API key from a profile of ~/.oci/config. Only that profile is read:
# missing values are never taken from DEFAULT.
provider "ociext" {
  config_file_profile = "PERSONAL"
  region              = "eu-frankfurt-1"
}
