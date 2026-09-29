# Networking-as-code: a VPC with public/private subnets, routing, and a
# baseline security group. Homelab analogy in comments: the same concepts I
# already run on-prem (VLANs, subnets, firewall rules), expressed as AWS code.

locals {
  common_tags = merge(var.tags, {
    Module    = "network"
    ManagedBy = "terraform"
  })
}

# VPC == the routed network behind my edge firewall at home.
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, { Name = "${var.name}-vpc" })
}

# Internet gateway == the WAN uplink.
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "${var.name}-igw" })
}

# Public subnets == the DMZ VLAN (internet-facing by policy).
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${var.name}-public-${var.azs[count.index]}"
    Tier = "public"
  })
}

# Private subnets == internal VLANs (no direct inbound from the internet).
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.name}-private-${var.azs[count.index]}"
    Tier = "private"
  })
}

# Public route table == a static default route out the WAN uplink.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = merge(local.common_tags, { Name = "${var.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Baseline security group == a default-deny firewall policy: no inbound,
# all egress. Callers tighten inbound per workload.
resource "aws_security_group" "baseline" {
  name        = "${var.name}-baseline"
  description = "Baseline: no inbound, all egress. Tighten per workload."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.name}-baseline-sg" })
}
