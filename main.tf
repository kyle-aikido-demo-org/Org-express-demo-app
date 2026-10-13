# INTENTIONALLY INSECURE Terraform for IaC scanning demos.
# DO NOT run `terraform apply` on this. Scan only (e.g. Aikido IaC scanning, tfsec, Checkov).
# All credentials below are fake.

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "my-demo-project"
  region  = "us-central1"
}

# ISSUE: hardcoded secret in source
variable "db_password" {
  type    = string
  default = "SuperSecretPassword123!"
}

locals {
  api_key = "AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKEFAKE00"
}

# ISSUE: bucket publicly readable, no uniform access, no versioning, no logging, no CMEK
resource "google_storage_bucket" "public_data" {
  name                        = "dast-demo-public-data"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = false
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public_data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# ISSUE: SSH and RDP open to the internet
resource "google_compute_firewall" "allow_all_ingress" {
  name          = "allow-ssh-rdp-anywhere"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
}

# ISSUE: public IP, default service account with full API scope, OS Login off,
# project-wide SSH keys allowed, serial port enabled, no disk encryption key, no Shielded VM
resource "google_compute_instance" "vm" {
  name         = "demo-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
    access_config {} # external IP
  }

  metadata = {
    enable-oslogin         = "FALSE"
    serial-port-enable     = "TRUE"
    block-project-ssh-keys = "FALSE"
    db_password            = var.db_password
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

# ISSUE: Cloud SQL with public IP open to the world, no SSL, no backups, no deletion protection
resource "google_sql_database_instance" "db" {
  name             = "demo-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  deletion_protection = false

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"

      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }

    backup_configuration {
      enabled = false
    }

    database_flags {
      name  = "log_connections"
      value = "off"
    }
  }
}

resource "google_sql_user" "admin" {
  name     = "postgres"
  instance = google_sql_database_instance.db.name
  password = var.db_password
}

# ISSUE: Cloud Run service open to everyone, secret passed as plain env var, ingress unrestricted
resource "google_cloud_run_v2_service" "app" {
  name     = "dast-demo"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = "gcr.io/my-demo-project/dast-demo:latest"

      env {
        name  = "DB_PASSWORD"
        value = var.db_password
      }
      env {
        name  = "API_KEY"
        value = local.api_key
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.app.name
  location = google_cloud_run_v2_service.app.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ISSUE: overly broad IAM, owner role granted to a user and a service account key created
resource "google_project_iam_member" "owner" {
  project = "my-demo-project"
  role    = "roles/owner"
  member  = "user:contractor@example.com"
}

resource "google_service_account" "deployer" {
  account_id = "deployer"
}

resource "google_service_account_key" "deployer_key" {
  service_account_id = google_service_account.deployer.name
}
