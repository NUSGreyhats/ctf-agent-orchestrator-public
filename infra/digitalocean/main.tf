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
  ssh_public_key = file(pathexpand(var.ssh_public_key_path))
}

# Compute the MD5 fingerprint of the SSH public key locally.
# DigitalOcean accepts fingerprints for keys already on the account,
# so this works regardless of whether the key was previously uploaded.
resource "null_resource" "ssh_key_upload" {
  triggers = {
    public_key = md5(local.ssh_public_key)
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${var.do_token}" \
        -d '{"name":"ctf-workstation","public_key":"${replace(local.ssh_public_key, "\n", "")}"}' \
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
  name       = "ctf-workstation"
  region     = var.region
  size       = var.droplet_size
  image      = "ubuntu-24-04-x64"
  ssh_keys   = [data.external.ssh_fingerprint.result.fingerprint]
  user_data  = file("${path.module}/startup.sh")
}

resource "digitalocean_firewall" "webapp" {
  name        = "allow-ctf-webapp"
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

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<-EOT
      set -euo pipefail

      IP="${digitalocean_droplet.ctf.ipv4_address}"
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
      echo "  URL:      https://$IP"
      echo "  Password: $(ssh $SSH_OPTS root@"$IP" cat /root/.ctf-solver-password)"
      echo "============================================"
      echo ""
    EOT
  }
}
