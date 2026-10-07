provider "aws" {
  profile = "claude-code"
  region  = var.region

  # Toutes les ressources taguables reçoivent automatiquement ces tags.
  default_tags {
    tags = local.common_tags
  }
}
