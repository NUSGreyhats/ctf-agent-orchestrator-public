terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

locals {
  repo_root      = abspath("${path.module}/../..")
  ssh_public_key = file(pathexpand(var.ssh_public_key_path))

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

# Compute the MD5 fingerprint of the SSH public key locally.
# DigitalOcean accepts fingerprints for keys already on the account,
# so this works regardless of whether the key was previously uploaded.
resource "null_resource" "ssh_key_upload" {
  triggers = {
    public_key = md5(trimspace(local.ssh_public_key))
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${var.do_token}" \
        -d '{"name":"${var.instance_name}-ssh","public_key":"${trimspace(local.ssh_public_key)}"}' \
        "https://api.digitalocean.com/v2/account/keys" \
        -o /dev/null -w "%%{http_code}" | grep -qE "^(201|422)$"
    EOT
  }
}

data "external" "ssh_fingerprint" {
  program = ["bash", "-c", <<-EOT
    FP=$(ssh-keygen -lf "${pathexpand(var.ssh_public_key_path)}" -E md5 2>/dev/null | awk '{print $2}' | sed 's/MD5://')
    echo "{\"fingerprint\": \"$FP\"}"
  EOT
  ]
}

resource "digitalocean_droplet" "ctf" {
  depends_on = [null_resource.ssh_key_upload]
  name       = var.instance_name
  region     = var.region
  size       = var.droplet_size
  image      = var.droplet_image
  ssh_keys   = [data.external.ssh_fingerprint.result.fingerprint]
  user_data  = file("${path.module}/startup.sh")
}

resource "digitalocean_firewall" "webapp" {
  name        = "${var.instance_name}-webapp-${digitalocean_droplet.ctf.id}"
  droplet_ids = [digitalocean_droplet.ctf.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "51820"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "null_resource" "provision" {
  depends_on = [digitalocean_droplet.ctf]

  # Run script even if droplet gets destroyed and recreated.
  triggers = {
    droplet_id = digitalocean_droplet.ctf.id
    sync_hash  = local.sync_hash
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      IP="${digitalocean_droplet.ctf.ipv4_address}"
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
