variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "llm-firewall"
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "llm-firewall"
    Environment = "lab"
    ManagedBy   = "terraform"
  }
}

variable "allowed_origins" {
  description = "Trusted browser origins allowed to call the firewall API"
  type        = list(string)

  validation {
    condition = length(var.allowed_origins) > 0 && alltrue([
      for origin in var.allowed_origins : can(regex("^https://", origin)) || can(regex("^http://localhost(:[0-9]+)?$", origin))
    ])
    error_message = "Provide at least one HTTPS origin (or an explicit localhost development origin)."
  }
}

variable "api_shared_secret" {
  description = "Shared secret required in the X-API-Key header when calling the firewall API"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.api_shared_secret) >= 32
    error_message = "The shared secret must contain at least 32 characters."
  }
}
