# Terraform configuration for dynamic Buildkite agent pool
# This creates an autoscaling group of NixOS EC2 instances

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region"
  default     = "us-west-2"
}

variable "buildkite_agent_token" {
  description = "Buildkite agent token"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "c6i.2xlarge"  # 8 vCPU, 16GB RAM - good for parallel builds
}

variable "min_agents" {
  description = "Minimum number of agents"
  default     = 1
}

variable "max_agents" {
  description = "Maximum number of agents"
  default     = 10
}

# Data sources
data "aws_ami" "nixos" {
  most_recent = true
  owners      = ["080433136561"]  # NixOS official AMI owner

  filter {
    name   = "name"
    values = ["nixos-23.11-*-x86_64-linux"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security group
resource "aws_security_group" "buildkite_agent" {
  name_prefix = "buildkite-agent-"
  description = "Security group for Buildkite agents"

  # Egress - allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Optional: SSH access for debugging
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrict this in production!
  }

  tags = {
    Name = "buildkite-agent"
  }
}

# IAM role for agents
resource "aws_iam_role" "buildkite_agent" {
  name_prefix = "buildkite-agent-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

# IAM policy for accessing secrets
resource "aws_iam_role_policy" "buildkite_agent_secrets" {
  name_prefix = "buildkite-agent-secrets-"
  role        = aws_iam_role.buildkite_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.github_token.arn,
          # Add other secrets here
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.nix_cache.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "buildkite_agent" {
  name_prefix = "buildkite-agent-"
  role        = aws_iam_role.buildkite_agent.name
}

# Secrets Manager
resource "aws_secretsmanager_secret" "github_token" {
  name_prefix = "buildkite/github-token-"
  description = "GitHub token for Buildkite agents"
}

resource "aws_secretsmanager_secret_version" "github_token" {
  secret_id     = aws_secretsmanager_secret.github_token.id
  secret_string = var.github_token  # Pass this as a variable
}

variable "github_token" {
  description = "GitHub token for releases"
  type        = string
  sensitive   = true
}

# S3 bucket for Nix binary cache (optional alternative to Cachix)
resource "aws_s3_bucket" "nix_cache" {
  bucket_prefix = "bpftrace-nix-cache-"
}

resource "aws_s3_bucket_lifecycle_configuration" "nix_cache" {
  bucket = aws_s3_bucket.nix_cache.id

  rule {
    id     = "expire-old-cache"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

# Launch template
resource "aws_launch_template" "buildkite_agent" {
  name_prefix   = "buildkite-agent-"
  image_id      = data.aws_ami.nixos.id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.buildkite_agent.arn
  }

  vpc_security_group_ids = [aws_security_group.buildkite_agent.id]

  # Enable IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # User data
  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    buildkite_agent_token = var.buildkite_agent_token
    github_token_secret   = aws_secretsmanager_secret.github_token.name
    nix_cache_bucket      = aws_s3_bucket.nix_cache.bucket
    aws_region            = var.aws_region
  }))

  # Root volume - needs space for Nix store
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 200  # GB - adjust based on needs
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      delete_on_termination = true
      encrypted             = true
    }
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "buildkite-agent"
      Role = "ci"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name = "buildkite-agent"
    }
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "buildkite_agents" {
  name_prefix         = "buildkite-agents-"
  vpc_zone_identifier = var.subnet_ids  # Pass these as variables
  min_size            = var.min_agents
  max_size            = var.max_agents
  desired_capacity    = var.min_agents

  launch_template {
    id      = aws_launch_template.buildkite_agent.id
    version = "$Latest"
  }

  # Health checks
  health_check_type         = "EC2"
  health_check_grace_period = 300

  # Termination policy - terminate oldest instances first
  termination_policies = ["OldestInstance"]

  tag {
    key                 = "Name"
    value               = "buildkite-agent"
    propagate_at_launch = true
  }

  tag {
    key                 = "ManagedBy"
    value               = "terraform"
    propagate_at_launch = true
  }
}

variable "subnet_ids" {
  description = "List of subnet IDs for the ASG"
  type        = list(string)
}

# CloudWatch-based scaling policies
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "buildkite-scale-up"
  autoscaling_group_name = aws_autoscaling_group.buildkite_agents.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 2
  cooldown               = 300
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "buildkite-scale-down"
  autoscaling_group_name = aws_autoscaling_group.buildkite_agents.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = 300
}

# Outputs
output "autoscaling_group_name" {
  value = aws_autoscaling_group.buildkite_agents.name
}

output "nix_cache_bucket" {
  value = aws_s3_bucket.nix_cache.bucket
}
