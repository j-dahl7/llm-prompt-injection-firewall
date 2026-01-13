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
