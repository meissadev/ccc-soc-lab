# Aucun port entrant depuis Internet. Seul le trafic interne au VPC est admis :
#  - agents Wazuh (bank -> SOC-01 : 1514/tcp événements, 1515/tcp enrôlement) ;
#  - échanges entre outils SOC (Shuffle <-> Wazuh <-> MISP <-> IRIS) ;
#  - trafic de test entre "bank" et une éventuelle instance d'attaque du VPC.
# La sortie est libre (images Docker, paquets, agent SSM en HTTPS).

resource "aws_security_group" "soc" {
  name        = "${var.project}-sg-soc"
  description = "SOC-01 / SOC-02 : entrant VPC uniquement"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.project}-sg-soc" }
}

resource "aws_security_group" "bank" {
  name        = "${var.project}-sg-bank"
  description = "DC01 / SRV-WEB : entrant VPC uniquement"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.project}-sg-bank" }
}

locals {
  security_groups = {
    soc  = aws_security_group.soc.id
    bank = aws_security_group.bank.id
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_vpc" {
  for_each = local.security_groups

  security_group_id = each.value
  description       = "Tout le trafic interne au VPC - Wazuh 1514/1515, tests bank/attaque, outils SOC"
  cidr_ipv4         = local.vpc_cidr
  ip_protocol       = "-1"

  tags = { Name = "${var.project}-${each.key}-in-vpc" }
}

resource "aws_vpc_security_group_egress_rule" "all_out" {
  for_each = local.security_groups

  security_group_id = each.value
  description       = "Sortie libre (Internet via IGW + VPC)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = { Name = "${var.project}-${each.key}-out-all" }
}
