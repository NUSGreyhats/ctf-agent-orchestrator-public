# Infrastructure

Three cloud providers are supported. Pick one and `cd` into its directory.

## Hetzner (`infra/hetzner/`)

```bash
cd infra/hetzner
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your Hetzner settings

terraform init
terraform plan
terraform apply

# Once done, SSH in with:
ssh -i ~/.ssh/id_rsa root@$(terraform output -raw external_ip)

# Get the web UI password:
terraform output -raw webapp_password

# Re-run only the long environment bootstrap:
terraform apply -replace=null_resource.setup_environment

# Re-deploy only the web app / service:
terraform apply -replace=null_resource.deploy_webapp

# To tear it down later:
terraform destroy
```

You can also omit `hcloud_token` from `terraform.tfvars` and export `HCLOUD_TOKEN` instead. Set `ssh_public_key_path` and `ssh_private_key_path` to a matching keypair if you are not using `~/.ssh/id_rsa(.pub)`.
Set `repo_path` to the repository root that contains `environment/` and `webapp/`. The default `../..` is correct when running from `infra/hetzner/`.

Hetzner VM specs are controlled in `variables.tf` / `terraform.tfvars` with `instance_name`, `location`, `server_type`, and `image`.

## DigitalOcean (`infra/digitalocean/`)

Get a DigitalOcean API token at: https://cloud.digitalocean.com/account/api/tokens

```bash
cd infra/digitalocean
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your DigitalOcean API token

terraform init
terraform plan
terraform apply

# Once done, SSH in with:
ssh root@$(terraform output -raw external_ip)

# To tear it down later:
terraform destroy
```

DigitalOcean VM specs are controlled in `variables.tf` / `terraform.tfvars` with `instance_name`, `region`, `droplet_size`, and `droplet_image`.

To verify or change the droplet size slug:
```bash
doctl compute size list | grep amd
```

## GCP (`infra/gcp/`)

```bash
cd infra/gcp
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your GCP project and VM settings

terraform init
terraform plan
terraform apply

# Once done, SSH in with:
ssh root@$(terraform output -raw external_ip)

# To tear it down later:
terraform destroy
```

GCP VM specs are controlled in `variables.tf` / `terraform.tfvars` with `instance_name`, `zone`, `machine_type`, `image`, `boot_disk_size_gb`, and `boot_disk_type`.
