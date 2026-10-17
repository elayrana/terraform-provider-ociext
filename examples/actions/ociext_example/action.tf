resource "terraform_data" "example" {
  input = "fake-string"

  lifecycle {
    action_trigger {
      events  = [before_create]
      actions = [action.ociext_example.example]
    }
  }
}

action "ociext_example" "example" {
  config {
    configurable_attribute = "some-value"
  }
}