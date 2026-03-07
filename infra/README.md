Make sure you have Terraform and gcloud CLI set up, then:

```bash
cd ~/all-things-ai/infra
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your GCP project ID

gcloud auth application-default login   # authenticate Terraform with GCP
terraform init                          # download providers
terraform plan                          # preview what will be created
terraform apply                         # create the VM and provision it

# Once done, SSH in with:
ssh root@$(terraform output -raw external_ip)

# To tear it down later:
terraform destroy
```

Installs in 13m20s on e2-standard-4.
