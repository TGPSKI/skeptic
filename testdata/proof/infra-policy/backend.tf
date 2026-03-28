terraform {
  backend "s3" {
    bucket = "my-state-bucket"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}
