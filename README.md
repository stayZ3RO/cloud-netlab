# cloud-netlab

> **At a glance**
> - **Problem:** explore network segmentation as reviewable, tested AWS infrastructure-as-code. The current home network is a flat UniFi LAN; VLAN and firewall segmentation are planned.
> - **Architecture:** a reusable `network` module (VPC, public/private subnets across AZs, IGW, routing, baseline security group) consumed by a `dev` environment; remote-state intent stubbed.
> - **Tech:** OpenTofu/Terraform (HCL), Python, pytest, GitHub Actions.
> - **Testing:** 101 pytest cases on the drift tool (pure logic + CLI, including security-group rule drift); `tofu validate` on the IaC.
> - **CI:** pushes to `main` on the GitHub mirror run `tofu fmt -check` + `validate` and `pytest` (green).
> - **Security:** no credentials/state/tfvars committed (`*.example` only); baseline SG is deny-inbound/allow-egress.
> - **What was actually run:** Locally, `tofu fmt`, `init -backend=false`, `validate`, and the full pytest suite pass. CI runs formatting/validation checks and the pytest suite on pushes to `main` on the GitHub mirror. No cloud resources were applied.
> - **Limitations (honest):** this is a **lab**. It demonstrates AWS IaC authoring, module design, and CI-gated testing; it does **not** represent production/enterprise AWS operations, multi-account architecture, or IAM/governance at scale.

## Why this exists

AWS **networking-as-code** with a real CI gate and a small, tested Python network-automation tool. Built to connect my homelab work with the AWS, module design, and tested automation expected in a platform / network automation role.

| Gap | Evidence in this repo |
| --- | --- |
| AWS + Terraform hands-on beyond my Proxmox IaC | AWS-targeted OpenTofu/Terraform in `iac/`, with a reusable VPC/subnet/routing/security-group module and remote-state intent stubbed |
| Reusable module design beyond flat root configs | `iac/environments/dev/` consumes `iac/modules/network/` |
| Tested application code beyond Bash/utility scripting | `tools/net-drift-check/` has pure comparison logic, CLI tests, and a pytest suite |
| CI-gated infrastructure | `.github/workflows/ci.yml` runs formatting, validation, and pytest on pushes to `main` on the GitHub mirror |

I picked *networking* on AWS on purpose: VPCs, subnets, routing, security groups. My home network currently runs on a UDM Pro and USW-24-PoE with a flat LAN. VLAN and firewall segmentation are planned there; this AWS lab explores those design questions without claiming they are deployed at home or in AWS.

## What's here

```
iac/
  modules/network/      reusable VPC/subnets/routing/SG module (not copy-pasted HCL)
  environments/dev/     consumes the module; one place to plan/apply
tools/
  net-drift-check/      tested Python CLI: compares desired vs actual network state, exits non-zero on drift
scripts/
  ci-local.sh           the same checks CI runs, runnable locally
.github/workflows/
  ci.yml                fmt + validate (IaC) and pytest (tool) on mirrored pushes to main
```

## The IaC

A reusable `network` module (VPC, public + private subnets across AZs, internet gateway, route table, baseline deny-inbound/allow-egress security group) consumed by an `environments/dev` root. Terraform and OpenTofu both run this: `terraform` and `tofu` are drop-in for these files.

```bash
cd iac/environments/dev
tofu fmt -recursive          # or terraform fmt
tofu init -backend=false     # no AWS creds needed to validate
tofu validate
# tofu plan                  # needs AWS creds; free-tier friendly
```

`fmt`, `init -backend=false`, and `validate` need **no** AWS account, so the whole thing is CI-checkable and reviewable without ever spending a cent. `plan`/`apply` are the only steps that touch AWS.

## The tool: net-drift-check

A small network-automation CLI that reads a **desired** network state (subnets, CIDRs, DNS records, and optional security-group rules in YAML) and an **actual** state, reports drift, and exits non-zero when they disagree. It's the kind of guardrail you'd wire into CI so infrastructure can't silently diverge from its definition.

Both inputs are supplied YAML snapshots. The CLI makes no AWS API calls and does not inspect deployed resources.

```bash
cd tools/net-drift-check
python3 -m pip install -r requirements.txt
python3 netdrift.py --desired expected.example.yaml --actual actual.example.yaml
python3 -m pytest -q          # tests
```

## CI

Forgejo is the primary Git host; GitHub is a push mirror, and CI runs only on GitHub mirror push events.

`.github/workflows/ci.yml` runs on pushes to `main` on that mirror: `tofu fmt -check` + `validate`, and `pytest` for the tool. `scripts/ci-local.sh` runs the identical checks locally (and a pre-commit hook can call it). If GitHub-hosted runners aren't available in a given org, the local script is the enforcement path, the same pattern I use at work.

## Evidence

The example command above reports a missing subnet, changed DNS, and security-group rule drift, then exits 1. [Main branch CI passed on 2026-09-28](https://github.com/stayZ3RO/cloud-netlab/actions/runs/36368451393). AWS console evidence would apply only after a future deployment; no cloud resources have been applied.

## Honesty

This is a lab, and it says so. It demonstrates AWS IaC authoring, reusable module design, remote-state intent, CI-gated infrastructure, and tested Python automation. It does **not** claim production AWS operations at scale. The live homelab is separate; this AWS design has not been deployed.

The drift checker is a focused utility rather than a product. Kubernetes deployment and continuous delivery are outside this lab's scope.

No credentials, account IDs, or state files are committed (`*.tfvars`, `*.tfstate`, `.env` are gitignored; only `*.example` is tracked).

More projects: [portfolio](https://chrisalorenzo.com/).
