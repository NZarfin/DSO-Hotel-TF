provider "aws" {
   region = "${var.aws_region}"
   default_tags {
      tags = {
         Environment = "${var.environment}"
         Service     = "dso_hotel_db"
         CreatedBy   = "NadavZ"
      }
  }
}