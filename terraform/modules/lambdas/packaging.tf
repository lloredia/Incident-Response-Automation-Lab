data "archive_file" "playbooks" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/../../../build/ir_automation.zip"
  excludes = [
    "**/__pycache__/**",
    "**/*.pyc",
  ]
}
