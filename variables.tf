# TIERED POLICY CREATION CONTROLS

variable "create_root_baseline_policy" {
  description = "Create baseline security policy for organization root (IAM, logging, regions, monitoring)"
  type        = bool
  default     = true
}

variable "create_prod_controls_policy" {
  description = "Create strict controls for production OU (encryption, deletion protection, network security)"
  type        = bool
  default     = true
}

variable "create_nonprod_controls_policy" {
  description = "Create development controls for non-production OU (cost limits, tagging, basic security)"
  type        = bool
  default     = true
}

# POLICY ATTACHMENT CONTROLS

variable "attach_root_policies" {
  description = "Attach baseline policies to organization root"
  type        = bool
  default     = false
}

variable "attach_prod_policies" {
  description = "Attach strict policies to production OU"
  type        = bool
  default     = false
}

variable "attach_nonprod_policies" {
  description = "Attach development policies to non-production OU"
  type        = bool
  default     = false
}

# OU TARGETING

variable "prod_ou_id" {
  description = "Production OU ID for policy attachment"
  type        = string
  default     = ""
}

variable "nonprod_ou_id" {
  description = "Non-production OU ID for policy attachment"  
  type        = string
  default     = ""
}
