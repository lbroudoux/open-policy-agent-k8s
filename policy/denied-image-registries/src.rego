package denied_image_registries

default is_gatekeeper = false

# Checks whether the policy 'input' has came from Gatekeeper
is_gatekeeper {
  has_field(input, "review")
  has_field(input.review, "object")
}

# Check the obj contains a field
has_field(obj, field) {
  obj[field]
}

# Get the input, as the input is not Gatekeeper based
object = input {
  not is_gatekeeper
}

# Get the input.review.object, as the input is Gatekeeper based
object = input.review.object {
  is_gatekeeper
}

# Set the .kind of the object we are currently working on
kind = object.kind

# @title Check a Pod image is not coming from denied registries
# @kinds core/Pod
violation[msg] {
  lower(kind) == "pod"
  some i
  image := object.spec.containers[i].image
  not startswith(image, "quay.io/")
  msg := sprintf("image '%v' comes from untrusted registry", [image])
}