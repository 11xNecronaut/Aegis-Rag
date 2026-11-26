variable "region" {
  description = "AWS region. Check that your chosen Bedrock models are available here before applying."
  type        = string
  default     = "ap-south-1"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "aegis"
}

variable "bedrock_model_arns" {
  description = "Exact foundation-model ARNs the app may invoke, e.g. arn:aws:bedrock:ap-south-1::foundation-model/<model-id>. No wildcards."
  type        = list(string)
  validation {
    condition     = length(var.bedrock_model_arns) > 0 && alltrue([for a in var.bedrock_model_arns : !strcontains(a, "*")])
    error_message = "Provide at least one explicit model ARN and no wildcards."
  }
}

variable "monthly_budget_usd" {
  description = "Hard alert threshold for the whole account in USD per month."
  type        = number
  default     = 20
}

variable "budget_alert_email" {
  description = "Where budget alerts are sent."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 365
}
