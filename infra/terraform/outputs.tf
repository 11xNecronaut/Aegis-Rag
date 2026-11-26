output "app_role_arn" {
  value       = aws_iam_role.app.arn
  description = "Attach to the Lambda or container that runs AegisRAG."
}

output "documents_bucket" {
  value = aws_s3_bucket.documents.id
}

output "api_tokens_secret_arn" {
  value = aws_secretsmanager_secret.api_tokens.arn
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "log_group" {
  value = aws_cloudwatch_log_group.app.name
}
