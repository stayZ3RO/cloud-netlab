#!/usr/bin/env python3
"""net-drift-check: compare a desired network state to an actual one.

Reads two YAML documents describing subnets, DNS records, and optional
security-group rules; reports any drift between them; and exits non-zero when
they disagree. The point is a CI-friendly guardrail: infrastructure should not
silently diverge from the definition that is supposed to describe it.

Usage:
    netdrift.py --desired desired.yaml --actual actual.yaml [--json]

Exit codes:
    0  no drift
    1  drift detected
    2  usage / input error
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without pyyaml installed
    print("error: pyyaml is required (pip install -r requirements.txt)", file=sys.stderr)
    sys.exit(2)


@dataclass
class DriftReport:
    """Structured result of a desired-vs-actual comparison."""

    missing_subnets: list[str] = field(default_factory=list)
    unexpected_subnets: list[str] = field(default_factory=list)
    missing_dns: list[str] = field(default_factory=list)
    unexpected_dns: list[str] = field(default_factory=list)
    changed_dns: list[str] = field(default_factory=list)
    missing_sg_rules: list[str] = field(default_factory=list)
    unexpected_sg_rules: list[str] = field(default_factory=list)
    security_groups_supplied: bool = False

    @property
    def has_drift(self) -> bool:
        return any(
            [
                self.missing_subnets,
                self.unexpected_subnets,
                self.missing_dns,
                self.unexpected_dns,
                self.changed_dns,
                self.missing_sg_rules,
                self.unexpected_sg_rules,
            ]
        )

    def as_dict(self) -> dict[str, list[str]]:
        data = {
            "missing_subnets": self.missing_subnets,
            "unexpected_subnets": self.unexpected_subnets,
            "missing_dns": self.missing_dns,
            "unexpected_dns": self.unexpected_dns,
            "changed_dns": self.changed_dns,
        }
        if self.security_groups_supplied or self.missing_sg_rules or self.unexpected_sg_rules:
            data["missing_sg_rules"] = self.missing_sg_rules
            data["unexpected_sg_rules"] = self.unexpected_sg_rules
        return data


_VALID_DIRECTIONS = {"ingress", "egress"}
_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "all"}
_RULE_FIELDS = {"direction", "protocol", "from_port", "to_port", "cidr"}


@dataclass(frozen=True)
class SecurityGroupRule:
    """A normalized, hashable security-group rule used as the unit of comparison."""

    group: str
    direction: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str

    def label(self) -> str:
        ports = "all" if self.from_port is None else f"{self.from_port}-{self.to_port}"
        return f"{self.group} {self.direction} {self.protocol} {ports} {self.cidr}"


def normalize_cidr(cidr: str) -> str:
    """Return a canonical CIDR string, raising ValueError on bad input.

    Normalizing means 10.30.0.0/24 and 10.30.0.5/24 compare equal by network,
    so cosmetic host-bit differences are not reported as drift.
    """
    if not isinstance(cidr, str):
        raise ValueError(f"CIDR must be a string, got {cidr!r}")
    return str(ipaddress.ip_network(cidr, strict=False))


def _subnet_set(state: dict[str, Any]) -> set[str]:
    return {normalize_cidr(c) for c in state.get("subnets", []) or []}


def _dns_map(state: dict[str, Any]) -> dict[str, str]:
    if "dns_records" not in state:
        return {}
    records = state["dns_records"]
    if not isinstance(records, dict):
        raise ValueError("dns_records must be a mapping of name -> value")
    return {str(k): str(v) for k, v in records.items()}


def normalize_security_group_rule(group: str, raw: Any) -> SecurityGroupRule:
    """Validate and normalize one security-group rule, raising ValueError on bad input."""
    if not isinstance(raw, dict):
        raise ValueError(f"security group {group!r}: each rule must be a mapping")

    unknown = sorted(repr(field_name) for field_name in raw if field_name not in _RULE_FIELDS)
    if unknown:
        raise ValueError(f"security group {group!r}: rule has unknown field(s) {unknown}")

    required = ("direction", "protocol", "cidr")
    missing = [field_name for field_name in required if field_name not in raw]
    if missing:
        raise ValueError(f"security group {group!r}: rule missing field(s) {missing}")

    if not isinstance(raw["direction"], str):
        raise ValueError(
            f"security group {group!r}: direction must be a string, got {raw['direction']!r}"
        )
    direction = raw["direction"].strip().lower()
    if direction not in _VALID_DIRECTIONS:
        raise ValueError(
            f"security group {group!r}: direction must be one of {sorted(_VALID_DIRECTIONS)}, got {raw['direction']!r}"
        )

    raw_protocol = raw["protocol"]
    if isinstance(raw_protocol, str):
        protocol = raw_protocol.strip().lower()
    elif type(raw_protocol) is int and raw_protocol == -1:
        protocol = "-1"
    else:
        raise ValueError(
            f"security group {group!r}: protocol must be one of {sorted(_VALID_PROTOCOLS | {'-1'})}, "
            f"got {raw_protocol!r}"
        )
    if protocol == "-1":
        protocol = "all"
    if protocol not in _VALID_PROTOCOLS:
        raise ValueError(
            f"security group {group!r}: protocol must be one of {sorted(_VALID_PROTOCOLS | {'-1'})}, "
            f"got {raw_protocol!r}"
        )

    if protocol == "all":
        for name in ("from_port", "to_port"):
            if name in raw and (not isinstance(raw[name], int) or isinstance(raw[name], bool)):
                raise ValueError(
                    f"security group {group!r}: {name} must be an integer when supplied, got {raw[name]!r}"
                )
        from_port = to_port = None
    else:
        missing_ports = [name for name in ("from_port", "to_port") if name not in raw]
        if missing_ports:
            raise ValueError(f"security group {group!r}: rule missing field(s) {missing_ports}")
        from_port, to_port = raw["from_port"], raw["to_port"]
        for name, value in (("from_port", from_port), ("to_port", to_port)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"security group {group!r}: {name} must be an integer, got {value!r}")

        if protocol in {"tcp", "udp"} and not (0 <= from_port <= to_port <= 65535):
            raise ValueError(
                f"security group {group!r}: port range {from_port}-{to_port} is invalid "
                "(must satisfy 0 <= from_port <= to_port <= 65535)"
            )
        if protocol in {"icmp", "icmpv6"}:
            for name, value in (("from_port", from_port), ("to_port", to_port)):
                if value != -1 and not 0 <= value <= 255:
                    raise ValueError(
                        f"security group {group!r}: {name} must be -1 or an integer from 0 through 255, "
                        f"got {value!r}"
                    )
            if from_port == -1 and to_port != -1:
                raise ValueError(
                    f"security group {group!r}: ICMP code must be -1 when ICMP type is -1"
                )

    try:
        cidr = normalize_cidr(raw["cidr"])
    except ValueError as exc:
        raise ValueError(f"security group {group!r}: invalid cidr field: {exc}") from exc

    return SecurityGroupRule(
        group=group,
        direction=direction,
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        cidr=cidr,
    )


def _security_group_rule_set(state: dict[str, Any]) -> set[SecurityGroupRule]:
    if "security_groups" not in state:
        return set()
    groups = state["security_groups"]
    if not isinstance(groups, dict):
        raise ValueError("security_groups must be a mapping of group -> list of rules")

    rules: set[SecurityGroupRule] = set()
    for group, group_rules in groups.items():
        if not isinstance(group, str):
            raise ValueError(f"security group identifiers must be strings, got {group!r}")
        if not isinstance(group_rules, list):
            raise ValueError(f"security_groups[{group!r}] must be a list of rules")
        for raw_rule in group_rules:
            rules.add(normalize_security_group_rule(group, raw_rule))
    return rules


def compare(desired: dict[str, Any], actual: dict[str, Any]) -> DriftReport:
    """Compare desired and actual network state and return a DriftReport."""
    report = DriftReport(
        security_groups_supplied="security_groups" in desired or "security_groups" in actual
    )

    desired_subnets = _subnet_set(desired)
    actual_subnets = _subnet_set(actual)
    report.missing_subnets = sorted(desired_subnets - actual_subnets)
    report.unexpected_subnets = sorted(actual_subnets - desired_subnets)

    desired_dns = _dns_map(desired)
    actual_dns = _dns_map(actual)
    report.missing_dns = sorted(set(desired_dns) - set(actual_dns))
    report.unexpected_dns = sorted(set(actual_dns) - set(desired_dns))
    report.changed_dns = sorted(
        name
        for name in set(desired_dns) & set(actual_dns)
        if desired_dns[name] != actual_dns[name]
    )

    desired_sg_rules = _security_group_rule_set(desired)
    actual_sg_rules = _security_group_rule_set(actual)
    report.missing_sg_rules = sorted(r.label() for r in desired_sg_rules - actual_sg_rules)
    report.unexpected_sg_rules = sorted(r.label() for r in actual_sg_rules - desired_sg_rules)

    return report


def _load(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            detail = getattr(exc, "problem", str(exc))
            raise ValueError(f"{path}: invalid YAML: {detail}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    return data


def render_text(report: DriftReport) -> str:
    if not report.has_drift:
        return "OK: no drift between desired and actual network state."
    lines = ["DRIFT DETECTED:"]
    labels = [
        ("missing_subnets", "Subnets in desired but not actual"),
        ("unexpected_subnets", "Subnets in actual but not desired"),
        ("missing_dns", "DNS records missing from actual"),
        ("unexpected_dns", "DNS records present but not desired"),
        ("changed_dns", "DNS records whose value differs"),
        ("missing_sg_rules", "Security-group rules in desired but not actual"),
        ("unexpected_sg_rules", "Security-group rules in actual but not desired"),
    ]
    data = report.as_dict()
    for key, label in labels:
        if data.get(key):
            lines.append(f"  {label}:")
            lines.extend(f"    - {item}" for item in data[key])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare desired vs actual network state.")
    parser.add_argument("--desired", required=True, help="Path to desired-state YAML.")
    parser.add_argument("--actual", required=True, help="Path to actual-state YAML.")
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    args = parser.parse_args(argv)

    try:
        desired = _load(args.desired)
        actual = _load(args.actual)
        report = compare(desired, actual)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(render_text(report))
    return 1 if report.has_drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
