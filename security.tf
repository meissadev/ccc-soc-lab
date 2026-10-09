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

# Sans VLSM : tout le trafic interne au VPC est admis.
resource "aws_vpc_security_group_ingress_rule" "from_vpc" {
  for_each = var.vlsm_enabled ? {} : local.security_groups

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

# Avec VLSM : segmentation par sous-réseau (moindre privilège entre segments).
#  - soc     <- soc   : tout (Wazuh <-> Shuffle <-> MISP <-> IRIS)
#  - soc     <- bank  : 1514-1515/tcp uniquement (événements et enrôlement des agents Wazuh)
#  - bank    <- bank  : tout (AD, DNS, applications)
#  - bank    <- soc   : tout (administration, investigation, tests du SOC)
#  - bank    <- attaque : tout (exercices Red Team, internes au VPC)
locals {
  vlsm_ingress = var.vlsm_enabled ? {
    soc-from-soc      = { sg = "soc", cidr = local.soc_cidr, proto = "-1", from = null, to = null, desc = "Outils SOC entre eux" }
    soc-wazuh-agents  = { sg = "soc", cidr = local.bank_cidr, proto = "tcp", from = 1514, to = 1515, desc = "Agents Wazuh (evenements 1514, enrolement 1515)" }
    bank-from-bank    = { sg = "bank", cidr = local.bank_cidr, proto = "-1", from = null, to = null, desc = "Serveurs de la banque entre eux" }
    bank-from-soc     = { sg = "bank", cidr = local.soc_cidr, proto = "-1", from = null, to = null, desc = "Administration et investigation depuis le SOC" }
    bank-from-attaque = { sg = "bank", cidr = local.attaque_cidr, proto = "-1", from = null, to = null, desc = "Exercices Red Team internes au VPC" }
  } : {}
}

resource "aws_vpc_security_group_ingress_rule" "vlsm" {
  for_each = local.vlsm_ingress

  security_group_id = local.security_groups[each.value.sg]
  description       = each.value.desc
  cidr_ipv4         = each.value.cidr
  ip_protocol       = each.value.proto
  from_port         = each.value.from
  to_port           = each.value.to

  tags = { Name = "${var.project}-${each.key}" }
}
