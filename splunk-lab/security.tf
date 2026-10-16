# Aucun port entrant depuis Internet. Segmentation VLSM entre segments (moindre privilège) :
#  - soc  <- soc     : tout (Splunk <-> Shuffle <-> MISP <-> IRIS)
#  - soc  <- bank    : 9997/tcp (Splunk Universal Forwarder) et 8088/tcp (HTTP Event Collector) uniquement
#  - bank <- bank    : tout (AD, DNS, applications)
#  - bank <- soc     : tout (administration, investigation, reponse du SOAR)
#  - bank <- attaque : tout (exercices Red Team internes au VPC)
# La sortie est libre (paquets, images Docker, agent SSM en HTTPS).

resource "aws_security_group" "soc" {
  name        = "${var.name_prefix}-sg-soc"
  description = "SPLUNK-01 / SOC-02 : entrant VPC uniquement"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.name_prefix}-sg-soc" }
}

resource "aws_security_group" "bank" {
  name        = "${var.name_prefix}-sg-bank"
  description = "DC01 / SRV-WEB : entrant VPC uniquement"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.name_prefix}-sg-bank" }
}

locals {
  security_groups = {
    soc  = aws_security_group.soc.id
    bank = aws_security_group.bank.id
  }

  ingress = {
    soc-from-soc      = { sg = "soc", cidr = local.soc_cidr, proto = "-1", from = null, to = null, desc = "Outils SOC entre eux" }
    soc-splunk-uf     = { sg = "soc", cidr = local.bank_cidr, proto = "tcp", from = 9997, to = 9997, desc = "Splunk Universal Forwarder" }
    soc-splunk-hec    = { sg = "soc", cidr = local.bank_cidr, proto = "tcp", from = 8088, to = 8088, desc = "Splunk HTTP Event Collector" }
    bank-from-bank    = { sg = "bank", cidr = local.bank_cidr, proto = "-1", from = null, to = null, desc = "Serveurs de la banque entre eux" }
    bank-from-soc     = { sg = "bank", cidr = local.soc_cidr, proto = "-1", from = null, to = null, desc = "Administration, investigation et reponse depuis le SOC" }
    bank-from-attaque = { sg = "bank", cidr = local.attaque_cidr, proto = "-1", from = null, to = null, desc = "Exercices Red Team internes au VPC" }
  }
}

resource "aws_vpc_security_group_egress_rule" "all_out" {
  for_each = local.security_groups

  security_group_id = each.value
  description       = "Sortie libre (Internet via IGW + VPC)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = { Name = "${var.name_prefix}-${each.key}-out-all" }
}

resource "aws_vpc_security_group_ingress_rule" "lab" {
  for_each = local.ingress

  security_group_id = local.security_groups[each.value.sg]
  description       = each.value.desc
  cidr_ipv4         = each.value.cidr
  ip_protocol       = each.value.proto
  from_port         = each.value.from
  to_port           = each.value.to

  tags = { Name = "${var.name_prefix}-${each.key}" }
}
