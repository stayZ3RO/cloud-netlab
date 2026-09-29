# net-drift-check

A small, tested network-automation CLI. It compares a **desired** network state (subnets, DNS records, and optional security-group rules) to an **actual** one and exits non-zero on drift, the kind of guardrail you wire into CI so infrastructure can't quietly diverge from its definition.

This is deliberately the same idea as the drift/validation discipline I run in my homelab (pre-build "is this subnet/IP free?" checks, config baselines), but here it's real Python with tests instead of shell one-offs.

## Run it

```bash
python3 -m pip install -r requirements.txt
python3 netdrift.py --desired expected.example.yaml --actual actual.example.yaml
# non-zero exit + a drift report, because actual.example.yaml intentionally drifts
python3 netdrift.py --desired expected.example.yaml --actual expected.example.yaml
# exit 0: no drift
```

## Test it

```bash
python3 -m pytest -q
```

## Security-group rule drift

The tool also compares **security-group rules**, under an optional `security_groups` key:

```yaml
security_groups:
  web-sg:
    - direction: ingress
      protocol: tcp
      from_port: 443
      to_port: 443
      cidr: 0.0.0.0/0
    - direction: egress
      protocol: tcp
      from_port: 0
      to_port: 65535
      cidr: 0.0.0.0/0
```

Supported protocols are deliberately limited to `tcp`, `udp`, `icmp`, `icmpv6`, and `all`; `-1` (quoted or unquoted in YAML) is accepted as an alias for `all`. TCP and UDP require integer `from_port` and `to_port` values from 0 through 65535 in ascending order. For ICMP and ICMPv6 those fields instead mean type and code: each accepts `-1` or 0 through 255, `-1/-1` means all types and codes, and a specific type with code `-1` deliberately means all codes for that type. If type is `-1`, code must also be `-1`.

**Rule identity** is the normalized tuple `(group, direction, protocol, from_port, to_port, cidr)`. For `all`, ports may be omitted and are canonicalized to `None`, so legacy `0/0`, `0/65535`, or other integer port values cannot create false drift. Direction/protocol are lowercased and CIDRs are canonicalized with `ipaddress` for both IPv4 and IPv6. Rules are compared as **sets**, not ordered lists: order and duplicate copies of the same identity do not create drift. A rule identity present only in `desired` is reported under `missing_sg_rules`; one present only in `actual` is reported under `unexpected_sg_rules`. Group names are part of identity and must be strings. Output is sorted by label, so reports are deterministic.

Rules accept exactly `direction`, `protocol`, `from_port`, `to_port`, and `cidr`; the port fields are optional only for `all`. TCP/UDP ports receive 0-65535 range and ordering validation, while ICMP/ICMPv6 values receive the type/code validation above. Legacy port fields supplied for `all` receive integer/non-Boolean type validation only, then are discarded from canonical identity and cannot create drift. Missing required fields, unknown fields (including `description`), unsupported protocols, non-string or malformed CIDRs, non-string group names, and malformed container structures are rejected rather than partially compared. Input errors, including malformed YAML syntax, produce a concise error and exit code `2`.

For backward compatibility, JSON output retains the original five fields when neither input contains `security_groups`. If either input supplies that key, even as an empty mapping, the JSON report also includes `missing_sg_rules` and `unexpected_sg_rules`.

As with subnets and DNS records, this operates purely on the two YAML documents you hand it, it does not query or modify AWS, and no cloud infrastructure was applied to build or test this feature.

## Design notes

- CIDRs are **normalized** (`ipaddress`), so `10.30.0.5/24` and `10.30.0.0/24` compare equal by network, cosmetic host-bit differences aren't false-positive drift.
- The comparison is pure and returns a structured `DriftReport`; the CLI is a thin wrapper. That separation is what makes it easy to test and easy to embed in a pipeline.
- `--json` emits machine-readable output for CI consumption.
- Exit codes: `0` no drift, `1` drift, `2` usage/input error.

## Fundamentals: why compare firewall rules this way

- **Sets, not lists.** A security group's rules have no meaningful order, a firewall enforces them all, not in list-position order. Comparing as an ordered list would report drift every time someone re-orders the same rules. Comparing normalized identities as a set also deliberately collapses duplicate copies of one rule.
- **Direction, protocol, protocol-specific ports, and CIDR matter together.** `ingress tcp 443-443 0.0.0.0/0` and `egress tcp 443-443 0.0.0.0/0` have opposite security implications. ICMP fields are type/code rather than an ordered range, while all-protocol port values are ignored because AWS ignores them.
- **Deterministic normalization is what makes this usable in CI.** `protocol: TCP` vs `tcp`, `all` vs `-1`, or a CIDR written with stray host bits are cosmetically different but semantically identical. Normalizing once, up front, lets `compare()` remain a pure function and keeps reports byte-for-byte reproducible.
