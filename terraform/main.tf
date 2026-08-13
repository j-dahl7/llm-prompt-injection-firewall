# LLM Prompt Injection Firewall
# Demonstrates an authenticated prompt-screening boundary
#
# Architecture:
# API Gateway -> Lambda screening -> allow/block JSON
#                    |
#                    +-> DynamoDB (bounded detection metadata)
#                    +-> CloudWatch (logs and derived metrics)
#
# No model backend is included or invoked.

terraform {
  required_version = ">= 1.0.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "= 2.8.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------------------------
# Lambda Function - Prompt Injection Firewall
# -----------------------------------------------------------------------------

data "archive_file" "lambda_zip" {
  type             = "zip"
  source_dir       = "${path.module}/../lambda"
  output_path      = "${path.module}/lambda.zip"
  output_file_mode = "0666"
  excludes         = ["__pycache__", "__pycache__/*", "*.pyc"]
}

resource "aws_lambda_function" "firewall" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-firewall"
  role             = aws_iam_role.lambda_role.arn
  handler          = "firewall.handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ATTACK_LOG_TABLE  = aws_dynamodb_table.attack_logs.name
      API_SHARED_SECRET = var.api_shared_secret
      LOG_LEVEL         = "INFO"
      BLOCK_MODE        = "true" # Set to "false" for detection-only mode
      MAX_PROMPT_LENGTH = "4000"
      ENABLE_PII_CHECK  = "true"
    }
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.lambda_logs.name
  }

  tags = var.tags

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_logging,
    aws_iam_role_policy_attachment.lambda_xray,
  ]
}

# Lambda IAM Role
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

# Lambda logging permission scoped to the pre-created function log group
resource "aws_iam_role_policy" "lambda_logging" {
  name = "${var.project_name}-lambda-logging"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
    }]
  })
}

# Lambda X-Ray tracing policy
resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# DynamoDB access for attack logging
resource "aws_iam_role_policy" "dynamodb_access" {
  name = "${var.project_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "dynamodb:PutItem"
      Resource = aws_dynamodb_table.attack_logs.arn
    }]
  })
}

# CloudWatch Logs
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-firewall"
  retention_in_days = 14

  tags = var.tags
}

# -----------------------------------------------------------------------------
# API Gateway - HTTP API for receiving prompts
# -----------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "prompt_api" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
  description   = "LLM Prompt Injection Firewall API"

  cors_configuration {
    allow_headers = ["Content-Type", "X-API-Key"]
    allow_methods = ["POST", "OPTIONS"]
    allow_origins = var.allowed_origins
    max_age       = 300
  }

  tags = var.tags
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.prompt_api.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      errorMessage   = "$context.error.message"
    })
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "api_logs" {
  name              = "/aws/apigateway/${var.project_name}"
  retention_in_days = 14

  tags = var.tags
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.prompt_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.firewall.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "prompt" {
  api_id    = aws_apigatewayv2_api.prompt_api.id
  route_key = "POST /prompt"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.firewall.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.prompt_api.execution_arn}/*/POST/prompt"
}

# -----------------------------------------------------------------------------
# DynamoDB - Attack Logging
# -----------------------------------------------------------------------------

resource "aws_dynamodb_table" "attack_logs" {
  name         = "${var.project_name}-attacks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "attack_id"
  range_key    = "timestamp"

  attribute {
    name = "attack_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "attack_type"
    type = "S"
  }

  global_secondary_index {
    name            = "by-attack-type"
    hash_key        = "attack_type"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# CloudWatch Monitoring
# -----------------------------------------------------------------------------

# Metrics are derived once from the handler's structured log entry. The Lambda
# does not also call PutMetricData, which would double-count each request.
resource "aws_cloudwatch_log_metric_filter" "blocked_attacks" {
  name           = "${var.project_name}-blocked"
  pattern        = "{ $.blocked = true }"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name

  metric_transformation {
    name          = "BlockedAttacks"
    namespace     = "LLMFirewall"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "allowed_prompts" {
  name           = "${var.project_name}-allowed"
  pattern        = "{ $.blocked = false }"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name

  metric_transformation {
    name          = "AllowedPrompts"
    namespace     = "LLMFirewall"
    value         = "1"
    default_value = "0"
  }
}

# Alarm for attack spike
resource "aws_cloudwatch_metric_alarm" "attack_spike" {
  alarm_name          = "${var.project_name}-attack-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedAttacks"
  namespace           = "LLMFirewall"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "High volume of blocked prompt injection attempts"

  tags = var.tags
}

# Alarm for errors
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.project_name}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Lambda function errors detected"

  dimensions = {
    FunctionName = aws_lambda_function.firewall.function_name
  }

  tags = var.tags
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "firewall" {
  dashboard_name = "${var.project_name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Blocked vs Allowed Prompts"
          region = var.aws_region
          metrics = [
            ["LLMFirewall", "BlockedAttacks", { color = "#d62728", label = "Blocked" }],
            ["LLMFirewall", "AllowedPrompts", { color = "#2ca02c", label = "Allowed" }]
          ]
          period = 300
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Lambda Performance"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "${var.project_name}-firewall", { stat = "Average" }],
            [".", "Invocations", ".", ".", { stat = "Sum", yAxis = "right" }]
          ]
          period = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          title  = "Recent Blocked Attacks"
          region = var.aws_region
          query  = "SOURCE '/aws/lambda/${var.project_name}-firewall' | fields @timestamp, attack_type, reason | filter blocked = true | sort @timestamp desc | limit 20"
        }
      }
    ]
  })
}
