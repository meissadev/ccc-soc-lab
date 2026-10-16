# Accès de l'équipe rouge (Roland) : policy IAM de moindre privilège.
# Elle n'autorise qu'une session Session Manager sur ATTAQUANT-01 et la gestion de ses
# propres sessions. Aucun accès à SPLUNK-01, SOC-02, DC01, SRV-WEB ni au reste du compte.
# Cette configuration ne crée que la POLICY : l'identité de Roland (utilisateur IAM) est
# créée à la main par l'équipe, puis cette policy lui est attachée.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_iam_policy" "roland_redteam" {
  name        = "${var.name_prefix}-redteam-roland"
  description = "Equipe rouge (Roland) : session SSM sur ATTAQUANT-01 uniquement."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Ouvrir un shell interactif sur la SEULE machine d'attaque.
        # On autorise StartSession sur l'instance ET sur le document de shell par défaut
        # (SSM-SessionManagerRunShell), ce qui couvre le cas où le contrôle de document
        # est activé dans le compte. Pas de port-forwarding ni de document de commande.
        Sid    = "StartSessionShellSurAttaquant"
        Effect = "Allow"
        Action = "ssm:StartSession"
        Resource = [
          aws_instance.attaquant.arn,
          "arn:aws:ssm:${data.aws_region.current.region}::document/SSM-SessionManagerRunShell"
        ]
      },
      {
        # Voir et terminer uniquement ses propres sessions.
        Sid    = "GererSesPropresSessions"
        Effect = "Allow"
        Action = [
          "ssm:TerminateSession",
          "ssm:ResumeSession"
        ]
        Resource = "arn:aws:ssm:*:*:session/$${aws:username}-*"
      },
      {
        # Lecture seule nécessaire à la console SSM (lister les sessions, décrire la machine).
        Sid    = "ConsoleSSMLectureSeule"
        Effect = "Allow"
        Action = [
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus",
          "ssm:DescribeInstanceInformation",
          "ssm:DescribeInstanceProperties",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

output "roland_policy_arn" {
  description = "ARN de la policy à attacher à l'utilisateur IAM de Roland (créé à la main)."
  value       = aws_iam_policy.roland_redteam.arn
}
