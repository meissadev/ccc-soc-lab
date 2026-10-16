# ATTAQUANT-01 : poste de l'équipe rouge pour le cyber drill (Roland).
# Dans le sous-réseau attaque (10.20.50.0/28), joignable par Session Manager uniquement.
# Le groupe de sécurité bank autorise déjà l'entrée depuis attaque_cidr (exercices internes au VPC).

resource "aws_security_group" "attaque" {
  name        = "${var.name_prefix}-sg-attaque"
  description = "ATTAQUANT-01 : aucune entree depuis Internet, sortie VPC + SSM"
  vpc_id      = aws_vpc.lab.id

  tags = { Name = "${var.name_prefix}-sg-attaque" }
}

resource "aws_vpc_security_group_egress_rule" "attaque_out" {
  security_group_id = aws_security_group.attaque.id
  description       = "Sortie libre (SSM en HTTPS + cibles internes au VPC)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = { Name = "${var.name_prefix}-attaque-out-all" }
}

resource "aws_instance" "attaquant" {
  ami                    = local.ubuntu_ami
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.attaque[0].id
  private_ip             = cidrhost(local.attaque_cidr, 9) # 10.20.50.9
  vpc_security_group_ids = [aws_security_group.attaque.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  # Pas de key pair : accès exclusivement via Session Manager.
  associate_public_ip_address = true
  user_data                   = file("${path.module}/cloud-init/attaquant.yaml")
  user_data_replace_on_change = true

  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
    tags                  = merge(local.common_tags, { Name = "ATTAQUANT-01-splunklab-root" })
  }

  tags = { Name = "ATTAQUANT-01 (lab Splunk, equipe rouge)" }

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  depends_on = [
    aws_route_table_association.attaque,
    aws_iam_role_policy_attachment.ssm_core,
  ]
}

output "attaquant_id" {
  description = "Identifiant de la machine d'attaque (equipe rouge)."
  value       = aws_instance.attaquant.id
}
