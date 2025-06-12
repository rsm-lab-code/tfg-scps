variable "create_iam_controls_policy" {
  description = "Create IAM security controls policy (root user, password policy, admin privileges, instance roles)"
  type        = bool
  default     = true
}

variable "create_data_storage_policy" {
  description = "Create data storage security policy (S3/EBS/RDS/EFS encryption, public access)"
  type        = bool
  default     = true
}

variable "create_logging_policy" {
  description = "Create logging protection policy (CloudTrail protection and encryption)"
  type        = bool
  default     = true
}

variable "create_monitoring_policy" {
  description = "Create monitoring protection policy (GuardDuty, VPC flow logs)"
  type        = bool
  default     = true
}

variable "create_networking_policy" {
  description = "Create networking security policy (admin ports, default SG, PrivateLink, TLS)"
  type        = bool
  default     = true
}

# Policy attachment variables
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