variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "llm-firewall"

  validation {
    condition = (
      length(var.project_name) >= 3 &&
      length(var.project_name) <= 40 &&
      can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.project_name))
    )
    error_message = "project_name must be 3-40 lowercase letters, digits, or hyphens and must start and end with a letter or digit."
  }
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
    condition = (
      length(var.allowed_origins) > 0 &&
      length(var.allowed_origins) <= 20 &&
      length(distinct(var.allowed_origins)) == length(var.allowed_origins) &&
      alltrue([
        for origin in var.allowed_origins : can(regex(
          "^https://([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])(:[0-9]{1,5})?$|^http://(localhost|127\\.0\\.0\\.1)(:[0-9]{1,5})?$",
          origin,
        ))
      ])
    )
    error_message = "allowed_origins must contain HTTPS origins, except HTTP is allowed for localhost development."
  }
}

variable "api_shared_secret" {
  description = "Shared secret required in the X-API-Key header when calling the firewall API"
  type        = string
  sensitive   = true

  validation {
    condition = (
      length(var.api_shared_secret) >= 32 &&
      length(var.api_shared_secret) <= 256 &&
      length(trimspace(var.api_shared_secret)) >= 32 &&
      !can(regex("[\\r\\n]", var.api_shared_secret))
    )
    error_message = "api_shared_secret must be 32-256 non-whitespace characters and cannot contain line breaks."
  }
}
