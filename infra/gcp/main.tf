terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = regex("^(.*)-[a-z]$", var.zone)[0]
  zone    = var.zone
}

resource "google_compute_instance" "ctf" {
  name         = "ctf-workstation"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.boot_disk_size_gb
      type  = "pd-ssd"
    }
  }

  network_interface {
    network = "default"

    access_config {}
  }

  tags = ["ctf-workstation"]

  metadata = {
    startup-script = file("${path.module}/startup.sh")
    ssh-keys       = "root:${file(pathexpand(var.ssh_public_key_path))}"
  }
}

resource "google_compute_firewall" "webapp" {
  name    = "allow-ctf-webapp"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ctf-workstation"]
}

resource "google_compute_firewall" "wireguard" {
  name    = "allow-ctf-wireguard"
  network = "default"

  allow {
    protocol = "udp"
    ports    = ["51820"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ctf-workstation"]
}

resource "null_resource" "provision" {
  depends_on = [google_compute_instance.ctf]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      set -euo pipefail

      IP="${google_compute_instance.ctf.network_interface[0].access_config[0].nat_ip}"
      SSH_KEY_PATH="${pathexpand(var.ssh_private_key_path)}"
      SSH_OPTS="-i $SSH_KEY_PATH -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
      step() { echo "==> $1"; }

      step "Waiting for SSH on $IP"
      until ssh $SSH_OPTS root@"$IP" true 2>/dev/null; do
        sleep 5
      done

      step "Copying repository to the VM"
      SRC_PATH="${var.all_things_ai_path}"
      SRC_PATH="$${SRC_PATH/#\~/$HOME}"
      scp -r $SSH_OPTS "$SRC_PATH" root@"$IP":/root/all-things-ai

      step "Running environment setup"
      ssh $SSH_OPTS root@"$IP" "bash /root/all-things-ai/environment/run.sh"

      step "Installing and starting ctf-solver.service"
      ssh $SSH_OPTS root@"$IP" "cp /root/all-things-ai/webapp/ctf-solver.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now ctf-solver"

      step "Waiting for generated web app password"
      ssh $SSH_OPTS root@"$IP" "timeout 300 bash -c 'until [ -f /root/.ctf-solver-password ]; do sleep 1; done'"

      echo ""
      echo "============================================"
      echo "  CTF Solver Web App"
      echo "  URL:      https://$IP:8080"
      echo "  Password: $(ssh $SSH_OPTS root@"$IP" cat /root/.ctf-solver-password)"
      echo "============================================"
      echo ""
    EOT
  }
}
