variable "attach_policies" {
  description = "Whether to attach SCP policies to the target OU"
  type        = bool
  default     = false
}

variable "target_ou_id" {
  description = "OU ID to attach policies to (empty = organization root)"
  type        = string
  default     = ""
}
