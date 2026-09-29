# Why this repo exists

This lab exists to close two specific, honestly-identified gaps between my homelab and operations work and a Software Engineer II (platform / network automation) role. It is deliberately small and deliberately real, a bridge artifact, not a résumé prop.

## The gaps it closes

| Gap (from my evidence audit) | How this repo answers it |
| --- | --- |
| **AWS + Terraform hands-on**, my Proxmox IaC proves lifecycle/blast-radius design but isn't AWS | `iac/` is AWS-targeted Terraform/OpenTofu: a reusable VPC/subnet/routing/SG module consumed by a `dev` environment, with remote-state intent stubbed |
| **Reusable module design**, my homelab IaC was flat root configs | `iac/modules/network/` is an actual module, consumed by `iac/environments/dev/` |
| **Tested application code**, my other code is Bash/utility scripting | `tools/net-drift-check/` is Python with a real `pytest` suite (pure comparison logic + CLI tests) |
| **CI-gated infrastructure**, my IaC had no pipeline | `.github/workflows/ci.yml` runs `fmt`/`validate` on the IaC and `pytest` on the tool, every push/PR |

## What it honestly does NOT claim

- Production AWS operations at scale. This is a small-scale learning lab.
- That the drift tool is a product. It's a focused, tested utility that demonstrates clean Python + testing + a network-automation instinct.
- Kubernetes/GitOps. Out of scope here; tracked separately in the homelab roadmap.

## How it connects to the rest of my work

The on-prem equivalents already run in my homelab: VLAN/subnet segmentation, HA DNS, firewall policy, drift/pre-build validation. This repo expresses that same thinking as AWS code with tests and CI, the exact translation the role is asking for.

See the full evidence audit and positioning in my private career notes.
