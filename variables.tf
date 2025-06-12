variable "ou_configurations" {
  description = "Configuration for each OU and their SCP policies"
  type = map(object({
    ou_id           = string
    policy_directory = string
    enabled         = bool
  }))
}
