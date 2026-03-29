output "function_arn" {
  value       = aws_lambda_function.this.arn
  description = "ARN of the deployed Lambda function"
}

output "function_url" {
  value       = aws_lambda_function_url.this.function_url
  description = "Lambda function URL endpoint"
}
