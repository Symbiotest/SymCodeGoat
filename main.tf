terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5"
}

provider "aws" { 
  region = var.aws_region
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Core Network
resource "aws_vpc" "enterprise_vpc_production" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "enterprise-web-platform---production-(terraform)-vpc"
    Environment = "production"
    Owner       = "infra-team"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.enterprise_vpc_production.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name        = "enterprise-web-public-subnet"
    Environment = "production"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.enterprise_vpc_production.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "us-east-1b"

  map_public_ip_on_launch = false

  tags = {
    Name        = "enterprise-web-private-subnet"
    Environment = "production"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.enterprise_vpc_production.id

  tags = {
    Name = "enterprise-web-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.enterprise_vpc_production.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "enterprise-web-public-rt"
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Groups
resource "aws_security_group" "alb_sg" {
  name   = "enterprise-web-alb-sg"
  vpc_id = aws_vpc.enterprise_vpc_production.id

  ingress {
    description = "HTTP from Internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "enterprise-web-alb-sg"
    Environment = "production"
  }
}

# Vulnerability 3: Add Description To Security Group (intentionally empty)
resource "aws_security_group" "web_sg" {
  name   = "enterprise-web-app-sg"
  vpc_id = aws_vpc.enterprise_vpc_production.id

  # Vulnerability: intentionally left description empty to demonstrate misconfig
  description = ""

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "enterprise-web-app-sg"
    Environment = "production"
  }
}

resource "aws_security_group" "rds_sg" {
  name   = "enterprise-web-rds-sg"
  vpc_id = aws_vpc.enterprise_vpc_production.id

  ingress {
    description = "Postgres access from web SG"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "enterprise-web-rds-sg"
    Environment = "production"
  }
}

# Load Balancing (ALB)
resource "aws_lb" "web_alb" {
  name               = "enterprise-web-alb-prod"
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_subnet.id]
  security_groups    = [aws_security_group.alb_sg.id]

  tags = {
    Name        = "enterprise-web-alb-prod"
    Environment = "production"
  }
}

resource "aws_lb_target_group" "web_tg" {
  name     = "enterprise-web-tg-prod"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.enterprise_vpc_production.id
}

resource "aws_lb_listener" "https_good" {
  load_balancer_arn = aws_lb.web_alb.arn
  port                = 443
  protocol            = "HTTPS"
  ssl_policy          = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn     = var.acm_cert_arn_good

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

# Vulnerability 0: Use Secure TLS Policy (Bad TLS policy)
resource "aws_lb_listener" "https_bad" {
  load_balancer_arn = aws_lb.web_alb.arn
  port                = 8443
  protocol            = "HTTPS"
  ssl_policy          = "ELBSecurityPolicy-TLS-1-1-2017-01"
  certificate_arn     = var.acm_cert_arn_bad

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

resource "aws_lb_target_group_attachment" "web_tg_attachment" {
  count            = 3
  target_group_arn =aws_lb_target_group.web_tg.arn
  target_id        = aws_instance.web_app[count.index].id
  port             = 80
}

# S3 - Object Storage
resource "aws_s3_bucket" "assets_bucket" {
  bucket = var.assets_bucket_name
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name        = "enterprise-web-assets-prod"
    Environment = "production"
  }
}

# S3 bucket for CloudTrail-like public logging (vulnerability 2: public log access)
resource "aws_s3_bucket" "cloudtrail_bucket_public" {
  bucket = var.cloudtrail_bucket_name
  acl    = "public-read"

  tags = {
    Name        = "enterprise-cloudtrail-logs-prod-public"
    Environment = "production"
  }
}

# EC2 – Web App Tier
resource "aws_instance" "web_app" {
  count             = 3
  ami               = data.aws_ami.amazon_linux_2.id
  instance_type     = var.instance_type
  subnet_id         = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  associate_public_ip_address = true
  iam_instance_profile       = aws_iam_instance_profile.ec2_profile.name

  root_block_device {
    encrypted = true
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name        = "enterprise-web-app-${count.index + 1}"
    Environment = "production"
  }
}

# RDS - Primary Database
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "enterprise-rds-subnet-group"
  subnet_ids = [aws_subnet.private_subnet.id]
}

resource "aws_db_subnet_group" "rds_swap" {
  # Placeholder to ensure naming in plan if needed (keep minimal for clarity)
  # Intentionally left unused in plan to avoid over-count.
  # This block is optional and kept for clarity; remove if strictly counting resources differently.
  count = 0
  name  = "unused-subnet-group"
  subnet_ids = [aws_subnet.private_subnet.id]
}

resource "aws_db_instance" "postgres_db" {
  identifier              = "enterprise-prod-postgres"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = false
  multi_az                = true
  db_subnet_group_name    = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  apply_immediately       = true
  auto_minor_version_upgrade = true

  performance_insights_enabled = true
  performance_insights_kms_key_id = ""  # Vulnerability: Customer-managed KMS key not provided
}

resource "aws_db_parameter_group" "rds_params" {
  name   = "enterprise-prod-rds-params"
  family = "postgres13"
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

# Observability & Security Monitoring
resource "aws_cloudwatch_log_group" "cw_log_good" {
  name              = "/aws/enterprise/prod/good"
  kms_key_id        = aws_kms_key.cw_kms.arn
  retention_in_days = 90
}

resource "aws_cloudwatch_log_group" "cw_log_bad" {
  name       = "/aws/enterprise/prod/bad"
  kms_key_id = ""  # Vulnerability: Log Group without customer key
  retention_in_days = 90
}

resource "aws_kms_key" "cw_kms" {
  description = "KMS key for CloudWatch Logs encryption"
  enable_key_rotation = true
}

# Observability/SEC: Additional artifact to address v1/v2 alignment (optional basic)
resource "aws_security_group_rule" "web_sg_ssh_open" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.web_sg.id
  cidr_blocks              = ["0.0.0.0/0"]  # Vulnerability: Open SSH from the Internet
  description              = "SSH access (intentionally open in production for vulnerability injection)"
}

# IAM for EC2
resource "aws_iam_role" "ec2_role" {
  name = "enterprise-web-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_s3_read" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "enterprise-web-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# Outputs