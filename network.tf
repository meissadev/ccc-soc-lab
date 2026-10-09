# VPC + Internet Gateway + route publique. Pas de NAT Gateway : chaque instance
# reçoit une IP publique auto-assignée (sortie uniquement, aucun port entrant
# ouvert depuis Internet). C'est aussi ce qui permet à l'agent SSM de joindre
# les endpoints Session Manager sans VPC endpoints (payants).

resource "aws_vpc" "lab" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = { Name = "${var.project}-igw" }
}

resource "aws_subnet" "soc" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = local.soc_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = { Name = "${var.project}-soc" }
}

resource "aws_subnet" "bank" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = local.bank_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = { Name = "${var.project}-bank" }
}

# Segment Red Team (VLSM uniquement) : accueille une future machine d'attaque.
resource "aws_subnet" "attaque" {
  count = var.vlsm_enabled ? 1 : 0

  vpc_id                  = aws_vpc.lab.id
  cidr_block              = local.attaque_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = { Name = "${var.project}-attaque" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

resource "aws_route_table_association" "soc" {
  subnet_id      = aws_subnet.soc.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "bank" {
  subnet_id      = aws_subnet.bank.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "attaque" {
  count = var.vlsm_enabled ? 1 : 0

  subnet_id      = aws_subnet.attaque[0].id
  route_table_id = aws_route_table.public.id
}
