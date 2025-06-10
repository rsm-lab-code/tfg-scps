variable "create_deny_root_policy" {
  description = "Create policy to deny root user actions"
  type        = bool
  default     = true
}

variable "create_cost_control_policy" {
  description = "Create policy to deny expensive instance types"
  type        = bool
  default     = true
}

variable "attach_policies" {
  description = "Attach policies to organization (set to false for testing)"
  type        = bool
  default     = false
}

variable "target_ou_id" {
  description = "OU ID to attach policies to (empty = organization root)"
  type        = string
  default     = ""
}
