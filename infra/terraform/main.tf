data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  log_group  = "/aegis/${var.name_prefix}/app"
}

# ------------------------------------------------------------------ encryption key
data "aws_iam_policy_document" "kms" {
  # checkov:skip=CKV_AWS_109: the account-root administration statement is the AWS-required default key policy.
  # checkov:skip=CKV_AWS_111: same statement; without it the key becomes unmanageable.
  # checkov:skip=CKV_AWS_356: key policies use resource "*" to mean "this key".
  statement {
    sid       = "EnableAccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
  statement {
    sid       = "AllowCloudWatchLogsForTheAppLogGroupOnly"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:${local.log_group}"]
    }
  }
}

resource "aws_kms_key" "main" {
  description             = "${var.name_prefix} data, secrets and log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.main.key_id
}

# ------------------------------------------------------------------ document bucket
resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_18: this IS the access-log target; logging a log bucket to itself is circular.
  # checkov:skip=CKV_AWS_144: cross-region replication is out of scope for a lab foundation.
  # checkov:skip=CKV2_AWS_62: no event consumers exist yet.
  bucket = "${var.name_prefix}-access-logs-${local.account_id}-${var.region}"
}

resource "aws_s3_bucket" "documents" {
  # checkov:skip=CKV_AWS_144: cross-region replication is out of scope for a lab foundation.
  # checkov:skip=CKV2_AWS_62: no event consumers exist yet.
  bucket = "${var.name_prefix}-documents-${local.account_id}-${var.region}"
}

locals {
  buckets = {
    access_logs = aws_s3_bucket.access_logs.id
    documents   = aws_s3_bucket.documents.id
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = local.buckets
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.buckets
  bucket   = each.value
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    id     = "housekeeping"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_logging" "documents" {
  bucket        = aws_s3_bucket.documents.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "documents/"
}

data "aws_iam_policy_document" "tls_only" {
  for_each = local.buckets
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:${local.partition}:s3:::${each.value}", "arn:${local.partition}:s3:::${each.value}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  for_each = local.buckets
  bucket   = each.value
  policy   = data.aws_iam_policy_document.tls_only[each.key].json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

# ------------------------------------------------------------------ secrets (container only; value is set out of band)
resource "aws_secretsmanager_secret" "api_tokens" {
  # checkov:skip=CKV2_AWS_57: tokens are issued by the identity provider (Cognito) in the target design; rotation lives there.
  name                    = "${var.name_prefix}/api-tokens"
  description             = "Per-tenant API credentials. Populate with: aws secretsmanager put-secret-value. Never commit values."
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 7
}

# ------------------------------------------------------------------ logs
resource "aws_cloudwatch_log_group" "app" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
}

# ------------------------------------------------------------------ least-privilege runtime identity
data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadExactlyOneSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.api_tokens.arn]
  }
  statement {
    sid       = "UseOnlyTheAppKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
  statement {
    sid       = "InvokeApprovedModelsOnly"
    actions   = ["bedrock:InvokeModel"]
    resources = var.bedrock_model_arns
  }
  statement {
    sid       = "ReadWriteDocumentPrefixOnly"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.documents.arn}/documents/*"]
  }
  statement {
    sid       = "ListDocumentPrefixOnly"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.documents.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["documents/*"]
    }
  }
  statement {
    sid       = "WriteOwnLogsOnly"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.app.arn}:*"]
  }
}

resource "aws_iam_role" "app" {
  name                 = "${var.name_prefix}-app"
  assume_role_policy   = data.aws_iam_policy_document.assume_lambda.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "app" {
  name   = "least-privilege"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

# ------------------------------------------------------------------ cost guard
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
