# GitLab + Terraform: Project Setup, Merge Requests & Multi-Environment Azure Deployment

A practical, end-to-end guide covering how to structure a Terraform project in GitLab, run it through merge requests, and deploy to multiple Azure environments (dev/staging/prod) with a proper CI/CD pipeline.

---

## 1. Create the GitLab Project

### Option A: New empty project
1. GitLab → **New Project** → **Create blank project**
2. Set visibility (Private for infra repos, almost always)
3. Initialize with a README
4. Clone locally: `git clone https://gitlab.com/<group>/<project>.git`

### Option B: Import from existing repo
GitLab → **New Project** → **Import project** → GitHub/Bitbucket/URL.

### Recommended repo structure for Terraform
```
infra-repo/
├── .gitlab-ci.yml
├── backend.tf
├── providers.tf
├── variables.tf
├── main.tf
├── outputs.tf
├── modules/
│   ├── network/
│   ├── app-service/
│   └── keyvault/
├── environments/
│   ├── dev/
│   │   ├── backend.tfvars
│   │   └── terraform.tfvars
│   ├── staging/
│   │   ├── backend.tfvars
│   │   └── terraform.tfvars
│   └── prod/
│       ├── backend.tfvars
│       └── terraform.tfvars
└── README.md
```

Key idea: **one set of root modules, environment-specific `.tfvars` and backend config** — not copy-pasted Terraform per environment. Keeps drift low and DRY.

---

## 2. Terraform State Backend on Azure

Store state remotely in an Azure Storage Account (never local state for team work).

```hcl
# backend.tf — partial config, values injected at init time
terraform {
  backend "azurerm" {}
}
```

Each environment's `backend.tfvars`:
```hcl
# environments/dev/backend.tfvars
resource_group_name  = "rg-tfstate-shared"
storage_account_name = "sttfstateshared"
container_name        = "tfstate"
key                    = "dev.terraform.tfstate"
```

Init per environment:
```bash
terraform init -backend-config=environments/dev/backend.tfvars
```

Set up the storage account once, manually or via a bootstrap pipeline (chicken-and-egg problem — this piece isn't itself Terraform-managed by the same state).

---

## 3. Azure Authentication for GitLab CI

Two common approaches:

### A. Service Principal + Client Secret (traditional)
Create an SP per environment (or one SP with environment-scoped roles):
```bash
az ad sp create-for-rbac --name "sp-terraform-dev" \
  --role "Contributor" \
  --scopes /subscriptions/<sub-id>/resourceGroups/<rg-name>
```
Store the output (`appId`, `password`, `tenant`) as **masked, protected CI/CD variables** in GitLab:
- `ARM_CLIENT_ID`
- `ARM_CLIENT_SECRET`
- `ARM_SUBSCRIPTION_ID`
- `ARM_TENANT_ID`

Set these per-environment using GitLab **Environment scopes** on CI/CD variables (Settings → CI/CD → Variables → set "Environment scope" to `dev`, `staging`, `prod` respectively) so each pipeline stage picks up the right identity automatically.

### B. Workload Identity Federation / OIDC (recommended, no secrets)
GitLab supports OIDC tokens (`CI_JOB_JWT_V2` / ID tokens) that Azure AD can trust via **Federated Credentials** on an App Registration. This avoids storing client secrets entirely.

```yaml
# .gitlab-ci.yml snippet
id_tokens:
  AZURE_ID_TOKEN:
    aud: api://AzureADTokenExchange
```
Then in Azure AD, configure a federated credential on the App Registration:
- Issuer: `https://gitlab.com`
- Subject: `project_path:<group>/<project>:ref_type:branch:ref:main` (or environment-scoped subject)

This is the more modern, secretless pattern — worth adopting if your Azure AD/Entra setup allows it, and given your CFC Insights work already uses Entra ID this pattern will feel familiar.

---

## 4. Branching & Merge Request Workflow

Typical flow for infra-as-code:

1. **Branch off `main`**: `git checkout -b feature/add-redis-cache`
2. **Make Terraform changes**, commit.
3. **Push and open a Merge Request (MR)** targeting `main`.
4. **Pipeline runs automatically** on the MR:
   - `terraform fmt -check`
   - `terraform validate`
   - `terraform plan` (against **dev**, typically) — plan output posted as an MR comment/artifact
5. **Reviewer(s) review the plan output** directly in the MR (not just the code diff — the *plan* is the real diff that matters for infra).
6. **Require approvals** (Settings → Merge requests → Approval rules) — e.g., 1–2 approvals, code owners for `environments/prod/**`.
7. **Merge** → triggers `terraform apply` against dev automatically (or on merge to main).
8. **Promote to staging/prod** via manual pipeline jobs (protected, gated) — see pipeline design below.

### GitLab settings worth enabling
- **Protected branches**: `main` protected, only maintainers can merge (or push disabled entirely, force via MR).
- **Merge request approval rules**: required approvers, optionally **Code Owners** file mapping `environments/prod/` to a senior/lead approver group.
- **Protected environments**: `staging` and `prod` environments require approval from designated users before a deployment job runs.
- **Merge trains** (optional, if multiple MRs land frequently) to serialize applies.

---

## 5. The Pipeline: Multi-Environment `.gitlab-ci.yml`

Design principle: **plan on every MR, apply only after merge, promote up the chain (dev → staging → prod) with manual gates.**

```yaml
stages:
  - validate
  - plan
  - apply-dev
  - apply-staging
  - apply-prod

variables:
  TF_VERSION: "1.8.5"
  TF_ROOT: ${CI_PROJECT_DIR}

.terraform_setup: &terraform_setup
  image: hashicorp/terraform:${TF_VERSION}
  before_script:
    - terraform --version

# ---------- VALIDATE (every MR) ----------
validate:
  <<: *terraform_setup
  stage: validate
  script:
    - terraform fmt -check -recursive
    - terraform init -backend=false
    - terraform validate
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

# ---------- PLAN (per environment, on MR) ----------
plan-dev:
  <<: *terraform_setup
  stage: plan
  environment:
    name: dev
  script:
    - terraform init -backend-config=environments/dev/backend.tfvars
    - terraform plan -var-file=environments/dev/terraform.tfvars -out=dev.tfplan
  artifacts:
    paths:
      - dev.tfplan
    expire_in: 1 week
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

# ---------- APPLY DEV (auto on merge to main) ----------
apply-dev:
  <<: *terraform_setup
  stage: apply-dev
  environment:
    name: dev
  script:
    - terraform init -backend-config=environments/dev/backend.tfvars
    - terraform apply -var-file=environments/dev/terraform.tfvars -auto-approve
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"'

# ---------- APPLY STAGING (manual gate) ----------
apply-staging:
  <<: *terraform_setup
  stage: apply-staging
  environment:
    name: staging
  script:
    - terraform init -backend-config=environments/staging/backend.tfvars
    - terraform plan -var-file=environments/staging/terraform.tfvars -out=staging.tfplan
    - terraform apply staging.tfplan
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"'
      when: manual
  needs: ["apply-dev"]

# ---------- APPLY PROD (manual gate, protected) ----------
apply-prod:
  <<: *terraform_setup
  stage: apply-prod
  environment:
    name: prod
  script:
    - terraform init -backend-config=environments/prod/backend.tfvars
    - terraform plan -var-file=environments/prod/terraform.tfvars -out=prod.tfplan
    - terraform apply prod.tfplan
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"'
      when: manual
  needs: ["apply-staging"]
```

### Why this shape works
- **`plan` on every MR** gives reviewers the actual infra diff before merge — this is the equivalent of a code review, but for infrastructure state.
- **`apply-dev` runs automatically** after merge — fast feedback, low risk environment.
- **`staging` and `prod` are `when: manual`** — a human must click "Run" in the GitLab pipeline UI, and if you mark those as **Protected Environments** (Settings → CI/CD → Environments), only specific users/groups can trigger or approve that click.
- **`needs:`** enforces the promotion order — you can't skip straight to prod.
- Azure creds (`ARM_*` variables) are injected automatically via GitLab CI/CD variables scoped per environment — no need to reference them explicitly in the YAML, the `azurerm` provider reads them from the environment.

---

## 6. Environment-Specific Variables

`environments/dev/terraform.tfvars`:
```hcl
environment       = "dev"
app_service_sku   = "B1"
instance_count    = 1
```

`environments/prod/terraform.tfvars`:
```hcl
environment       = "prod"
app_service_sku   = "P1v3"
instance_count    = 3
```

Reference `var.environment` inside modules to name/tag resources consistently (`rg-cfc-insights-${var.environment}`, etc.).

---

## 7. Protecting Prod Further

- **Protected Environments**: require specific approvers to authorize the `apply-prod` job run itself (separate from MR approval).
- **Required approvals on MR + CODEOWNERS**: a change touching `environments/prod/**` needs sign-off from your architecture/lead group.
- **`terraform plan` artifact review**: make plan output a required read before the manual apply job — reviewers should read the actual plan, not just trust the YAML.
- **State locking**: `azurerm` backend handles this natively via blob leases — prevents concurrent applies from corrupting state.
- **Drift detection**: add a scheduled pipeline (GitLab **Scheduled Pipelines**) running `terraform plan` nightly against prod with no apply, alerting if drift is detected.

---

## 8. Typical Day-to-Day Flow (Summary)

1. Engineer branches, edits `.tf` files, opens MR.
2. Pipeline auto-runs: fmt/validate/plan(dev) — plan visible in MR.
3. Reviewer reads code diff **and** plan output, approves.
4. MR merged to `main` → `apply-dev` runs automatically.
5. Once dev looks good, someone with staging permissions clicks **Run** on `apply-staging`.
6. Once staging is validated, someone with prod permissions clicks **Run** on `apply-prod`.
7. Each `apply` is tied to a GitLab **Environment**, so you get a deployment history/timeline per environment in GitLab's Environments view — similar to what you'd see in Harness, just GitLab-native.

---

## Notes / Where This Differs from Harness (Your Current Stack)

Since your day job stack uses Harness CI/CD, the conceptual mapping is:

| Harness concept | GitLab equivalent |
|---|---|
| Pipeline | `.gitlab-ci.yml` (stages/jobs) |
| Stage approval gates | Protected Environments + `when: manual` |
| Environments | GitLab Environments |
| Secrets manager | GitLab CI/CD Variables (masked/protected) or Azure Key Vault integration |
| Triggers | `rules:` blocks (`merge_request_event`, `push`, branch conditions) |

The Terraform structure (backend, module layout, tfvars-per-environment) is identical regardless of which CI tool drives it — that part is CI-agnostic.
