terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.60"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

locals {
  repo_root = abspath("${path.module}/../..")

  install_script_files = sort(fileset(local.repo_root, "install_scripts/**"))
  hook_files           = sort(fileset(local.repo_root, "hooks/**"))
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
    local.install_script_files,
    local.hook_files,
    local.mcp_files,
    local.webapp_files,
    local.skill_files,
    local.doc_files,
  ))

  install_scripts_hash = sha256(join("", [
    for f in concat(local.install_script_files, local.hook_files, local.skill_files) : "${f}:${filesha256("${local.repo_root}/${f}")}"
  ]))

  webapp_hash = sha256(join("", [
    for f in concat(local.webapp_files, local.skill_files) : "${f}:${filesha256("${local.repo_root}/${f}")}"
  ]))

  sync_hash = sha256(join("", [
    for f in local.sync_files : "${f}:${filesha256("${local.repo_root}/${f}")}"
  ]))
}

resource "hcloud_ssh_key" "ctf" {
  name       = "${var.instance_name}-ssh"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "hcloud_firewall" "ctf" {
  name = "${var.instance_name}-firewall"

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = [
      "0.0.0.0/0",
      "::/0",
    ]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "443"
    source_ips = [
      "0.0.0.0/0",
      "::/0",
    ]
  }

  rule {
    direction = "in"
    protocol  = "udp"
    port      = "51820"
    source_ips = [
      "0.0.0.0/0",
      "::/0",
    ]
  }
}

resource "hcloud_server" "ctf" {
  name        = var.instance_name
  server_type = var.server_type
  location    = var.location
  image       = var.image
  user_data   = file("${path.module}/startup.sh")

  ssh_keys = [hcloud_ssh_key.ctf.id]

  firewall_ids = [hcloud_firewall.ctf.id]
}

resource "null_resource" "sync_repo" {
  depends_on = [hcloud_server.ctf]

  triggers = {
    sync_hash = local.sync_hash
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      IP="${hcloud_server.ctf.ipv4_address}"
      SSH_KEY_PATH="${pathexpand(var.ssh_private_key_path)}"
      SSH_OPTS="-i $SSH_KEY_PATH -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
      step() { echo "==> $1"; }

      step "Validating local source path"
      SRC_PATH="${var.repo_path}"
      SRC_PATH="$${SRC_PATH/#\~/$HOME}"
      SRC_PATH="$(cd "$SRC_PATH" && pwd)"
      if [ ! -d "$SRC_PATH" ]; then
        echo "Local source path not found: $SRC_PATH" >&2
        exit 1
      fi

      step "Waiting for SSH on $IP"
      until ssh $SSH_OPTS root@"$IP" true 2>/dev/null; do
        sleep 5
      done

      step "Copying runtime files to the VM"
      tar -C "$SRC_PATH" --exclude-vcs \
        --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
        --exclude='.DS_Store' -cf - \
        install_scripts webapp skills mcps hooks README.md DESIGN.md \
        | ssh $SSH_OPTS root@"$IP" "TMP_DIR=\$(mktemp -d /root/ctf-agent-wrapper.sync.XXXXXX) && trap 'rm -rf \"\$TMP_DIR\"' EXIT && mkdir -p /root/ctf-agent-wrapper /root/ctf-agent-wrapper/challenges /root/ctf-agent-wrapper/state /root/ctf-agent-wrapper/all-skills && tar -C \"\$TMP_DIR\" -xf - && find /root/ctf-agent-wrapper -mindepth 1 -maxdepth 1 -not -name challenges -not -name state -not -name all-skills -exec rm -rf {} + && cp -a \"\$TMP_DIR\"/. /root/ctf-agent-wrapper/"
    EOT
  }
}

resource "null_resource" "setup_environment" {
  depends_on = [null_resource.sync_repo]

  triggers = {
    install_scripts_hash = local.install_scripts_hash
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      IP="${hcloud_server.ctf.ipv4_address}"
      SSH_KEY_PATH="${pathexpand(var.ssh_private_key_path)}"
      SSH_OPTS="-i $SSH_KEY_PATH -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
      step() { echo "==> $1"; }

      step "Waiting for SSH on $IP"
      until ssh $SSH_OPTS root@"$IP" true 2>/dev/null; do
        sleep 5
      done

      step "Running install script setup"
      ssh $SSH_OPTS root@"$IP" "bash /root/ctf-agent-wrapper/install_scripts/run.sh"
    EOT
  }
}

resource "null_resource" "deploy_webapp" {
  depends_on = [
    null_resource.sync_repo,
    null_resource.setup_environment,
  ]

  triggers = {
    webapp_hash = local.webapp_hash
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      IP="${hcloud_server.ctf.ipv4_address}"
      WEBAPP_PASSWORD_FILE="${path.module}/.webapp-password"
      SSH_KEY_PATH="${pathexpand(var.ssh_private_key_path)}"
      SSH_OPTS="-i $SSH_KEY_PATH -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
      step() { echo "==> $1"; }

      step "Waiting for SSH on $IP"
      until ssh $SSH_OPTS root@"$IP" true 2>/dev/null; do
        sleep 5
      done

      step "Installing and starting ctf-solver.service"
      ssh $SSH_OPTS root@"$IP" "cp /root/ctf-agent-wrapper/webapp/ctf-solver.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable ctf-solver && systemctl restart ctf-solver"

      step "Waiting for generated web app password"
      ssh $SSH_OPTS root@"$IP" "timeout 300 bash -c 'until [ -f /root/.ctf-solver-password ]; do sleep 1; done'"

      step "Saving web app password locally"
      umask 077
      ssh $SSH_OPTS root@"$IP" cat /root/.ctf-solver-password > "$WEBAPP_PASSWORD_FILE"
      echo ""
      echo "============================================"
      echo "  CTF Solver Web App"
      echo "  URL:      https://$IP"
      echo "  Password: $(cat "$WEBAPP_PASSWORD_FILE")"
      echo ""
      echo "  Next Steps:"
      echo "  Run: ssh root@$IP -i $SSH_KEY_PATH"
      echo "  Run: claude auth login"
      echo "  Run: codex login"
      echo "============================================"
      echo ""
    EOT
  }
}

data "local_file" "webapp_password" {
  filename   = "${path.module}/.webapp-password"
  depends_on = [null_resource.deploy_webapp]
}
