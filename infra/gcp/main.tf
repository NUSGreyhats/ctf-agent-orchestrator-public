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

locals {
  repo_root = abspath("${path.module}/../..")

  environment_files = sort(fileset(local.repo_root, "environment/**"))
  hook_files        = sort(fileset(local.repo_root, "hooks/**"))
  mcp_files = sort([
    for f in fileset(local.repo_root, "mcps/**") : f
    if !can(regex("(^|/)__pycache__/", f)) && !can(regex("\\.py[co]$", f))
  ])
  webapp_files = sort([
    for f in fileset(local.repo_root, "webapp/**") : f
    if !can(regex("(^|/)__pycache__/", f)) && !can(regex("\\.py[co]$", f))
  ])
  skill_files = sort(fileset(local.repo_root, "skills/**"))
  doc_files   = ["README.md", "DESIGN.md"]

  sync_files = distinct(concat(
    local.environment_files,
    local.hook_files,
    local.mcp_files,
    local.webapp_files,
    local.skill_files,
    local.doc_files,
  ))

  sync_hash = sha256(join("", [
    for f in local.sync_files : "${f}:${filesha256("${local.repo_root}/${f}")}"
  ]))
}

resource "google_compute_instance" "ctf" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork

    access_config {}
  }

  tags = [var.instance_name]

  metadata = {
    startup-script = file("${path.module}/startup.sh")
    ssh-keys       = "root:${file(pathexpand(var.ssh_public_key_path))}"
  }
}

resource "google_compute_firewall" "webapp" {
  name    = "allow-${var.instance_name}-webapp"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [var.instance_name]
}

resource "google_compute_firewall" "wireguard" {
  name    = "allow-${var.instance_name}-wireguard"
  network = var.network

  allow {
    protocol = "udp"
    ports    = ["51820"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [var.instance_name]
}

resource "null_resource" "provision" {
  depends_on = [google_compute_instance.ctf]

  triggers = {
    instance_id = google_compute_instance.ctf.id
    sync_hash   = local.sync_hash
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      IP="${google_compute_instance.ctf.network_interface[0].access_config[0].nat_ip}"
      SSH_KEY_PATH="${pathexpand(var.ssh_private_key_path)}"
      SSH_OPTS="-i $SSH_KEY_PATH -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
      step() { echo "==> $1"; }

      step "Waiting for SSH on $IP"
      until ssh $SSH_OPTS root@"$IP" true 2>/dev/null; do
        sleep 5
      done

      step "Copying runtime files to the VM"
      SRC_PATH="${var.repo_path}"
      SRC_PATH="$${SRC_PATH/#\~/$HOME}"
      SRC_PATH="$(cd "$SRC_PATH" && pwd)"
      tar -C "$SRC_PATH" --exclude-vcs \
        --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
        --exclude='.DS_Store' -cf - \
        environment webapp skills mcps hooks README.md DESIGN.md \
        | ssh $SSH_OPTS root@"$IP" "TMP_DIR=\$(mktemp -d /root/ctf-agent-wrapper.sync.XXXXXX) && trap 'rm -rf \"\$TMP_DIR\"' EXIT && mkdir -p /root/ctf-agent-wrapper /root/ctf-agent-wrapper/challenges /root/ctf-agent-wrapper/state && tar -C \"\$TMP_DIR\" -xf - && find /root/ctf-agent-wrapper -mindepth 1 -maxdepth 1 -not -name challenges -not -name state -exec rm -rf {} + && cp -a \"\$TMP_DIR\"/. /root/ctf-agent-wrapper/"

      step "Running environment setup"
      ssh $SSH_OPTS root@"$IP" "bash /root/ctf-agent-wrapper/environment/run.sh"

      step "Installing and starting ctf-solver.service"
      ssh $SSH_OPTS root@"$IP" "cp /root/ctf-agent-wrapper/webapp/ctf-solver.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable ctf-solver && systemctl restart ctf-solver"

      step "Waiting for generated web app password"
      ssh $SSH_OPTS root@"$IP" "timeout 300 bash -c 'until [ -f /root/.ctf-solver-password ]; do sleep 1; done'"

      echo ""
      echo "============================================"
      echo "  CTF Solver Web App"
      echo "  URL:      https://$IP"
      echo "  Password: $(ssh $SSH_OPTS root@"$IP" cat /root/.ctf-solver-password)"
      echo "============================================"
      echo ""
    EOT
  }
}
