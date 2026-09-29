"""Tests for netdrift. Run with: python3 -m pytest -q"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import netdrift


def test_normalize_cidr_canonicalizes_host_bits():
    # A host address inside a /24 normalizes to the network address.
    assert netdrift.normalize_cidr("10.30.0.5/24") == "10.30.0.0/24"


def test_normalize_cidr_rejects_garbage():
    with pytest.raises(ValueError):
        netdrift.normalize_cidr("not-a-cidr")


@pytest.mark.parametrize("cidr", [True, 0, 1.5, None, [], {}])
def test_normalize_cidr_rejects_non_strings(cidr):
    with pytest.raises(ValueError, match="CIDR must be a string"):
        netdrift.normalize_cidr(cidr)


def test_normalize_cidr_canonicalizes_ipv6_host_bits():
    assert netdrift.normalize_cidr("2001:db8::1/64") == "2001:db8::/64"


def test_no_drift_when_identical():
    state = {
        "subnets": ["10.30.0.0/24", "10.30.10.0/24"],
        "dns_records": {"gw.lab": "10.30.0.1"},
    }
    report = netdrift.compare(state, dict(state))
    assert not report.has_drift


def test_detects_missing_and_unexpected_subnets():
    desired = {"subnets": ["10.30.0.0/24", "10.30.1.0/24"]}
    actual = {"subnets": ["10.30.0.0/24", "10.30.99.0/24"]}
    report = netdrift.compare(desired, actual)
    assert report.missing_subnets == ["10.30.1.0/24"]
    assert report.unexpected_subnets == ["10.30.99.0/24"]
    assert report.has_drift


def test_host_bit_difference_is_not_drift():
    # Same network, cosmetic host-bit difference, must NOT be flagged.
    desired = {"subnets": ["10.30.0.0/24"]}
    actual = {"subnets": ["10.30.0.7/24"]}
    assert not netdrift.compare(desired, actual).has_drift


def test_detects_changed_and_missing_dns():
    desired = {"dns_records": {"gw.lab": "10.30.0.1", "dns.lab": "10.30.0.2"}}
    actual = {"dns_records": {"gw.lab": "10.30.0.254"}}
    report = netdrift.compare(desired, actual)
    assert report.changed_dns == ["gw.lab"]
    assert report.missing_dns == ["dns.lab"]
    assert report.has_drift


def test_invalid_dns_records_type_raises():
    with pytest.raises(ValueError):
        netdrift.compare({"dns_records": ["not", "a", "map"]}, {})


@pytest.mark.parametrize("side", ["desired", "actual"])
@pytest.mark.parametrize("value", [[], False, 0, "", None])
def test_present_invalid_dns_records_rejected_on_both_sides(side, value):
    desired, actual = ({"dns_records": value}, {})
    if side == "actual":
        desired, actual = actual, desired
    with pytest.raises(ValueError, match="dns_records must be a mapping"):
        netdrift.compare(desired, actual)


def test_absent_and_empty_dns_records_are_valid():
    assert not netdrift.compare({}, {}).has_drift
    assert not netdrift.compare({"dns_records": {}}, {"dns_records": {}}).has_drift


def _rule(direction="ingress", protocol="tcp", from_port=443, to_port=443, cidr="0.0.0.0/0"):
    return {
        "direction": direction,
        "protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
        "cidr": cidr,
    }


def test_no_sg_drift_regardless_of_list_order():
    desired = {
        "security_groups": {
            "web-sg": [
                _rule(direction="ingress", from_port=443, to_port=443),
                _rule(direction="egress", from_port=0, to_port=65535),
            ]
        }
    }
    actual = {
        "security_groups": {
            "web-sg": [
                _rule(direction="egress", from_port=0, to_port=65535),
                _rule(direction="ingress", from_port=443, to_port=443),
            ]
        }
    }
    assert not netdrift.compare(desired, actual).has_drift


def test_missing_expected_ingress_rule():
    desired = {"security_groups": {"web-sg": [_rule()]}}
    actual = {"security_groups": {"web-sg": []}}
    report = netdrift.compare(desired, actual)
    assert report.missing_sg_rules == ["web-sg ingress tcp 443-443 0.0.0.0/0"]
    assert not report.unexpected_sg_rules
    assert report.has_drift


def test_unexpected_actual_ingress_rule():
    desired = {"security_groups": {"web-sg": []}}
    actual = {"security_groups": {"web-sg": [_rule(from_port=22, to_port=22)]}}
    report = netdrift.compare(desired, actual)
    assert report.unexpected_sg_rules == ["web-sg ingress tcp 22-22 0.0.0.0/0"]
    assert not report.missing_sg_rules


def test_egress_rule_drift_missing_and_unexpected():
    desired = {
        "security_groups": {
            "web-sg": [_rule(direction="egress", protocol="tcp", from_port=0, to_port=65535)]
        }
    }
    actual = {
        "security_groups": {
            "web-sg": [_rule(direction="egress", protocol="udp", from_port=0, to_port=65535)]
        }
    }
    report = netdrift.compare(desired, actual)
    assert report.missing_sg_rules == ["web-sg egress tcp 0-65535 0.0.0.0/0"]
    assert report.unexpected_sg_rules == ["web-sg egress udp 0-65535 0.0.0.0/0"]


def test_protocol_difference_is_drift():
    desired = {"security_groups": {"web-sg": [_rule(protocol="tcp")]}}
    actual = {"security_groups": {"web-sg": [_rule(protocol="udp")]}}
    report = netdrift.compare(desired, actual)
    assert report.has_drift
    assert any("tcp" in r for r in report.missing_sg_rules)
    assert any("udp" in r for r in report.unexpected_sg_rules)


def test_protocol_normalization_treats_all_and_negative_one_as_equal():
    desired = {"security_groups": {"web-sg": [_rule(protocol="-1", from_port=0, to_port=65535)]}}
    actual = {"security_groups": {"web-sg": [_rule(protocol="ALL", from_port=0, to_port=65535)]}}
    report = netdrift.compare(desired, actual)
    assert not report.has_drift
    normalized = netdrift.normalize_security_group_rule("web-sg", desired["security_groups"]["web-sg"][0])
    assert normalized.protocol == "all"
    assert normalized.from_port is None
    assert normalized.to_port is None


def test_integer_negative_one_protocol_matches_all_and_string_alias():
    integer_alias = _rule(protocol=-1, from_port=123, to_port=456)
    string_alias = _rule(protocol="-1", from_port=0, to_port=65535)
    canonical_all = {
        "direction": "ingress",
        "protocol": "all",
        "cidr": "0.0.0.0/0",
    }
    normalized = {
        netdrift.normalize_security_group_rule("web-sg", rule)
        for rule in (integer_alias, string_alias, canonical_all)
    }
    assert len(normalized) == 1
    assert normalized.pop().from_port is None


def test_all_protocol_allows_omitted_ports():
    rule = {
        "direction": "egress",
        "protocol": "all",
        "cidr": "0.0.0.0/0",
    }
    normalized = netdrift.normalize_security_group_rule("web-sg", rule)
    assert normalized.from_port is None
    assert normalized.to_port is None


def test_all_protocol_ignores_supplied_port_values_for_identity():
    desired = {"security_groups": {"web-sg": [_rule(protocol="all", from_port=0, to_port=0)]}}
    actual = {"security_groups": {"web-sg": [_rule(protocol="-1", from_port=0, to_port=65535)]}}
    assert not netdrift.compare(desired, actual).has_drift


@pytest.mark.parametrize("protocol", ["icmp", "icmpv6"])
def test_icmp_echo_request_accepts_type_8_code_0(protocol):
    normalized = netdrift.normalize_security_group_rule(
        "ping-sg", _rule(protocol=protocol, from_port=8, to_port=0)
    )
    assert (normalized.from_port, normalized.to_port) == (8, 0)


@pytest.mark.parametrize("protocol", ["icmp", "icmpv6"])
def test_icmp_accepts_all_types_and_codes(protocol):
    normalized = netdrift.normalize_security_group_rule(
        "ping-sg", _rule(protocol=protocol, from_port=-1, to_port=-1)
    )
    assert (normalized.from_port, normalized.to_port) == (-1, -1)


def test_icmp_accepts_specific_type_with_all_codes():
    normalized = netdrift.normalize_security_group_rule(
        "ping-sg", _rule(protocol="icmp", from_port=8, to_port=-1)
    )
    assert (normalized.from_port, normalized.to_port) == (8, -1)


def test_icmp_rejects_values_outside_type_and_code_range():
    with pytest.raises(ValueError, match="0 through 255"):
        netdrift.normalize_security_group_rule(
            "ping-sg", _rule(protocol="icmp", from_port=65535, to_port=65535)
        )


def test_icmp_all_types_requires_all_codes():
    with pytest.raises(ValueError, match="code must be -1"):
        netdrift.normalize_security_group_rule(
            "ping-sg", _rule(protocol="icmp", from_port=-1, to_port=0)
        )


def test_unsupported_protocol_raises():
    with pytest.raises(ValueError, match="protocol must be one of"):
        netdrift.normalize_security_group_rule("web-sg", _rule(protocol="bogus"))


def test_unknown_rule_field_raises_and_names_field():
    rule = _rule()
    rule["description"] = "not modeled"
    with pytest.raises(ValueError, match="unknown field.*description"):
        netdrift.normalize_security_group_rule("web-sg", rule)


@pytest.mark.parametrize("protocol", ["tcp", "udp", "icmp", "icmpv6"])
def test_protocols_other_than_all_require_ports(protocol):
    rule = _rule(protocol=protocol)
    del rule["to_port"]
    with pytest.raises(ValueError, match="to_port"):
        netdrift.normalize_security_group_rule("web-sg", rule)


@pytest.mark.parametrize("protocol", ["tcp", "udp", "icmp", "icmpv6", "all"])
def test_boolean_ports_are_rejected(protocol):
    with pytest.raises(ValueError, match="from_port must be an integer"):
        netdrift.normalize_security_group_rule(
            "web-sg", _rule(protocol=protocol, from_port=True)
        )


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize(
    ("from_port", "to_port"),
    [
        (-1, 0),
        (0, -1),
        (65536, 65536),
        (0, 65536),
        (443, 80),
    ],
)
def test_tcp_udp_reject_invalid_port_boundaries(protocol, from_port, to_port):
    with pytest.raises(ValueError, match="port range"):
        netdrift.normalize_security_group_rule(
            "web-sg", _rule(protocol=protocol, from_port=from_port, to_port=to_port)
        )


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize(
    ("from_port", "to_port"),
    [
        (0, 0),
        (65535, 65535),
        (0, 65535),
    ],
)
def test_tcp_udp_accept_valid_port_boundaries(protocol, from_port, to_port):
    normalized = netdrift.normalize_security_group_rule(
        "web-sg", _rule(protocol=protocol, from_port=from_port, to_port=to_port)
    )
    assert (normalized.from_port, normalized.to_port) == (from_port, to_port)


def test_port_range_difference_is_drift():
    desired = {"security_groups": {"web-sg": [_rule(from_port=443, to_port=443)]}}
    actual = {"security_groups": {"web-sg": [_rule(from_port=440, to_port=450)]}}
    assert netdrift.compare(desired, actual).has_drift


def test_cidr_difference_is_drift():
    desired = {"security_groups": {"web-sg": [_rule(cidr="10.30.0.0/24")]}}
    actual = {"security_groups": {"web-sg": [_rule(cidr="10.30.1.0/24")]}}
    assert netdrift.compare(desired, actual).has_drift


def test_cidr_host_bits_normalized_in_sg_rules():
    desired = {"security_groups": {"web-sg": [_rule(cidr="10.30.0.0/24")]}}
    actual = {"security_groups": {"web-sg": [_rule(cidr="10.30.0.5/24")]}}
    assert not netdrift.compare(desired, actual).has_drift


def test_ipv6_cidr_host_bits_normalized_in_sg_rules():
    desired = {"security_groups": {"web-sg": [_rule(cidr="2001:db8::/64")]}}
    actual = {"security_groups": {"web-sg": [_rule(cidr="2001:db8::1/64")]}}
    assert not netdrift.compare(desired, actual).has_drift


def test_multiple_security_groups_do_not_collide():
    desired = {
        "security_groups": {
            "web-sg": [_rule(from_port=443, to_port=443)],
            "db-sg": [_rule(from_port=5432, to_port=5432, cidr="10.30.0.0/24")],
        }
    }
    actual = {
        "security_groups": {
            "web-sg": [_rule(from_port=443, to_port=443)],
            "db-sg": [_rule(from_port=5432, to_port=5432, cidr="10.30.0.0/24")],
        }
    }
    assert not netdrift.compare(desired, actual).has_drift

    actual_wrong_group = {
        "security_groups": {
            "web-sg": [_rule(from_port=443, to_port=443)],
            "other-sg": [_rule(from_port=5432, to_port=5432, cidr="10.30.0.0/24")],
        }
    }
    report = netdrift.compare(desired, actual_wrong_group)
    assert report.has_drift
    assert any("db-sg" in r for r in report.missing_sg_rules)
    assert any("other-sg" in r for r in report.unexpected_sg_rules)


def test_non_string_security_group_identifier_is_rejected_before_collision():
    desired = {"security_groups": {1: [_rule()]}}
    actual = {"security_groups": {"1": [_rule()]}}
    with pytest.raises(ValueError, match="identifiers must be strings"):
        netdrift.compare(desired, actual)


def test_duplicate_security_group_rules_are_collapsed_as_a_set():
    rule = _rule()
    desired = {"security_groups": {"web-sg": [rule, dict(rule)]}}
    actual = {"security_groups": {"web-sg": [dict(rule)]}}
    assert not netdrift.compare(desired, actual).has_drift


def test_sg_rule_report_ordering_is_deterministic():
    desired = {
        "security_groups": {
            "web-sg": [
                _rule(direction="egress", from_port=0, to_port=65535),
                _rule(direction="ingress", from_port=443, to_port=443),
            ]
        }
    }
    actual = {"security_groups": {"web-sg": []}}
    report1 = netdrift.compare(desired, actual)
    report2 = netdrift.compare(desired, actual)
    assert report1.missing_sg_rules == report2.missing_sg_rules
    assert report1.missing_sg_rules == sorted(report1.missing_sg_rules)


def test_malformed_sg_rule_missing_field_raises():
    bad = {
        "security_groups": {
            "web-sg": [{"direction": "ingress", "protocol": "tcp", "from_port": 443}]
        }
    }
    with pytest.raises(ValueError):
        netdrift.compare(bad, {})


def test_malformed_sg_rule_bad_direction_raises():
    bad = {"security_groups": {"web-sg": [_rule(direction="sideways")]}}
    with pytest.raises(ValueError):
        netdrift.compare(bad, {})


def test_malformed_sg_rule_non_integer_port_raises():
    bad_rule = _rule()
    bad_rule["from_port"] = "not-a-port"
    bad = {"security_groups": {"web-sg": [bad_rule]}}
    with pytest.raises(ValueError):
        netdrift.compare(bad, {})


def test_malformed_sg_rule_bad_cidr_raises():
    bad = {"security_groups": {"web-sg": [_rule(cidr="not-a-cidr")]}}
    with pytest.raises(ValueError):
        netdrift.compare(bad, {})


def test_security_groups_must_be_mapping():
    with pytest.raises(ValueError):
        netdrift.compare({"security_groups": ["not", "a", "mapping"]}, {})


@pytest.mark.parametrize("value", [[], False, 0, "", None])
def test_present_security_groups_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="security_groups must be a mapping"):
        netdrift.compare({"security_groups": value}, {})


def test_security_group_rules_must_be_list():
    with pytest.raises(ValueError):
        netdrift.compare({"security_groups": {"web-sg": "not-a-list"}}, {})


def test_cli_reports_sg_rule_drift(tmp_path: Path, capsys):
    desired = _write(
        tmp_path,
        "d.yaml",
        "security_groups:\n"
        "  web-sg:\n"
        "    - direction: ingress\n"
        "      protocol: tcp\n"
        "      from_port: 443\n"
        "      to_port: 443\n"
        "      cidr: 0.0.0.0/0\n",
    )
    actual = _write(tmp_path, "a.yaml", "security_groups:\n  web-sg: []\n")
    rc = netdrift.main(["--desired", desired, "--actual", actual, "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["missing_sg_rules"] == ["web-sg ingress tcp 443-443 0.0.0.0/0"]


def _write(tmp_path: Path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_cli_exit_zero_on_match(tmp_path: Path):
    desired = _write(tmp_path, "d.yaml", "subnets: ['10.30.0.0/24']\n")
    actual = _write(tmp_path, "a.yaml", "subnets: ['10.30.0.0/24']\n")
    rc = netdrift.main(["--desired", desired, "--actual", actual])
    assert rc == 0


def test_empty_yaml_document_remains_valid_empty_state(tmp_path: Path):
    empty = _write(tmp_path, "empty.yaml", "")
    assert netdrift._load(empty) == {}


@pytest.mark.parametrize("body", ["[]\n", "false\n", "0\n", '""\n'])
def test_cli_rejects_false_valued_non_mapping_top_level(tmp_path: Path, capsys, body):
    desired = _write(tmp_path, "d.yaml", body)
    actual = _write(tmp_path, "a.yaml", "{}\n")
    assert netdrift.main(["--desired", desired, "--actual", actual]) == 2
    assert "top-level YAML must be a mapping" in capsys.readouterr().err


@pytest.mark.parametrize("cidr", ["true", "0"])
def test_cli_rejects_boolean_and_integer_yaml_cidrs(tmp_path: Path, capsys, cidr):
    desired = _write(
        tmp_path,
        "d.yaml",
        "security_groups:\n"
        "  web-sg:\n"
        "    - direction: ingress\n"
        "      protocol: tcp\n"
        "      from_port: 443\n"
        "      to_port: 443\n"
        f"      cidr: {cidr}\n",
    )
    actual = _write(tmp_path, "a.yaml", "{}\n")
    assert netdrift.main(["--desired", desired, "--actual", actual]) == 2
    assert "CIDR must be a string" in capsys.readouterr().err


def test_cli_legacy_json_schema_is_exact_without_security_groups(tmp_path: Path, capsys):
    desired = _write(tmp_path, "d.yaml", "subnets: ['10.30.0.0/24']\n")
    actual = _write(tmp_path, "a.yaml", "subnets: ['10.30.0.0/24']\n")
    assert netdrift.main(["--desired", desired, "--actual", actual, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert list(payload) == [
        "missing_subnets",
        "unexpected_subnets",
        "missing_dns",
        "unexpected_dns",
        "changed_dns",
    ]


def test_json_includes_sg_fields_when_dimension_is_supplied(tmp_path: Path, capsys):
    desired = _write(tmp_path, "d.yaml", "security_groups: {}\n")
    actual = _write(tmp_path, "a.yaml", "{}\n")
    assert netdrift.main(["--desired", desired, "--actual", actual, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert list(payload) == [
        "missing_subnets",
        "unexpected_subnets",
        "missing_dns",
        "unexpected_dns",
        "changed_dns",
        "missing_sg_rules",
        "unexpected_sg_rules",
    ]
    assert payload["missing_sg_rules"] == []
    assert payload["unexpected_sg_rules"] == []


def test_cli_malformed_yaml_returns_two_without_traceback(tmp_path: Path, capsys):
    desired = _write(tmp_path, "d.yaml", "security_groups: [\n")
    actual = _write(tmp_path, "a.yaml", "{}\n")
    assert netdrift.main(["--desired", desired, "--actual", actual]) == 2
    captured = capsys.readouterr()
    assert "invalid YAML" in captured.err
    assert "Traceback" not in captured.err


def test_cli_exit_one_on_drift_with_json(tmp_path: Path, capsys):
    desired = _write(tmp_path, "d.yaml", "subnets: ['10.30.0.0/24']\n")
    actual = _write(tmp_path, "a.yaml", "subnets: ['10.30.1.0/24']\n")
    rc = netdrift.main(["--desired", desired, "--actual", actual, "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["missing_subnets"] == ["10.30.0.0/24"]


def test_cli_usage_error_on_missing_file(tmp_path: Path):
    rc = netdrift.main(["--desired", str(tmp_path / "nope.yaml"), "--actual", str(tmp_path / "nope2.yaml")])
    assert rc == 2
