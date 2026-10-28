from pathlib import Path
from typing import Any

import pytest

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.SecurityGroupUnrestrictedIngress3306 import SecurityGroupUnrestrictedIngress3306
from checkov.terraform.runner import Runner


@pytest.mark.parametrize("overrides, expected", [
    ({}, CheckResult.FAILED),
    ({"protocol": ["6"]}, CheckResult.FAILED),
    ({"protocol": [6]}, CheckResult.FAILED),
    ({"from_port": [3200], "to_port": [3400]}, CheckResult.FAILED),
    ({"from_port": ["3306"], "to_port": ["3306"]}, CheckResult.FAILED),
    ({"protocol": ["-1"], "from_port": [0], "to_port": [0]}, CheckResult.FAILED),
    ({"cidr_blocks": [[]], "ipv6_cidr_blocks": [["::/0"]]}, CheckResult.FAILED),
    ({"cidr_blocks": [["10.0.0.0/8", "0.0.0.0/0"]]}, CheckResult.FAILED),
    ({"cidr_blocks": [["var.source", "0.0.0.0/0"]]}, CheckResult.FAILED),
    ({"self": [True]}, CheckResult.FAILED),
    ({"prefix_list_ids": [["pl-example"]]}, CheckResult.FAILED),
    ({"cidr_blocks": [["127.0.0.1/32"]]}, CheckResult.PASSED),
    ({"cidr_blocks": [["10.42.0.0/16"]]}, CheckResult.PASSED),
    ({"cidr_blocks": [["203.0.113.0/24"]]}, CheckResult.PASSED),
    ({"cidr_blocks": [[]], "ipv6_cidr_blocks": [["::1/128"]]}, CheckResult.PASSED),
    ({"cidr_blocks": [[]], "source_security_group_id": ["sg-example"]}, CheckResult.PASSED),
    ({"cidr_blocks": [[]], "security_groups": [["sg-example"]]}, CheckResult.PASSED),
    ({"cidr_blocks": [[]], "prefix_list_ids": [["pl-example"]]}, CheckResult.PASSED),
    ({"cidr_blocks": [[]], "self": [True]}, CheckResult.PASSED),
    ({"protocol": ["udp"]}, CheckResult.PASSED),
    ({"protocol": [17]}, CheckResult.PASSED),
    ({"protocol": ["icmp"]}, CheckResult.PASSED),
    ({"from_port": [0], "to_port": [0]}, CheckResult.PASSED),
    ({"from_port": [3307], "to_port": [3400]}, CheckResult.PASSED),
    ({"from_port": [3000], "to_port": [3305]}, CheckResult.PASSED),
    ({"type": ["egress"]}, CheckResult.PASSED),
    ({"type": ["var.direction"]}, CheckResult.UNKNOWN),
    ({"protocol": ["var.protocol"]}, CheckResult.UNKNOWN),
    ({"protocol": []}, CheckResult.UNKNOWN),
    ({"from_port": ["var.port"]}, CheckResult.UNKNOWN),
    ({"to_port": []}, CheckResult.UNKNOWN),
    ({"from_port": [True]}, CheckResult.UNKNOWN),
    ({"from_port": [3306.5]}, CheckResult.UNKNOWN),
    ({"from_port": [3400], "to_port": [3200]}, CheckResult.UNKNOWN),
    ({"to_port": [65536]}, CheckResult.UNKNOWN),
    ({"cidr_blocks": [["var.source"]]}, CheckResult.UNKNOWN),
    ({"cidr_blocks": [["not-a-cidr"]]}, CheckResult.UNKNOWN),
    ({"cidr_blocks": [[]]}, CheckResult.UNKNOWN),
])
def test_rule(overrides: dict[str, Any], expected: CheckResult) -> None:
    conf = {
        "type": ["ingress"], "protocol": ["tcp"], "from_port": [3306],
        "to_port": [3306], "cidr_blocks": [["0.0.0.0/0"]],
    }
    conf.update(overrides)
    assert SecurityGroupUnrestrictedIngress3306().scan_resource_conf(conf) == expected


@pytest.mark.parametrize("cidr", ["::/0", "0:0:0:0:0:0:0:0/0", "0000:0000:0000:0000:0000:0000:0000:0000/0"])
def test_modern_ipv6(cidr: str) -> None:
    conf = {"ip_protocol": ["tcp"], "from_port": [3306], "to_port": [3306], "cidr_ipv6": [cidr]}
    assert SecurityGroupUnrestrictedIngress3306().scan_resource_conf(conf) == CheckResult.FAILED


def test_modern_all_protocols_without_ports() -> None:
    conf = {"ip_protocol": ["-1"], "cidr_ipv4": ["0.0.0.0/0"]}
    assert SecurityGroupUnrestrictedIngress3306().scan_resource_conf(conf) == CheckResult.FAILED


def test_inline_unknown_does_not_mask_public_rule() -> None:
    rule = SecurityGroupUnrestrictedIngress3306()
    conf = {"ingress": [
        {"protocol": ["tcp"], "from_port": [3306], "to_port": [3306], "cidr_blocks": [["var.source"]]},
        {"protocol": ["tcp"], "from_port": [3306], "to_port": [3306], "cidr_blocks": [["0.0.0.0/0"]]},
    ]}
    assert rule.scan_resource_conf(conf) == CheckResult.FAILED
    assert "ingress/[1]/cidr_blocks" in rule.evaluated_keys
    assert rule.scan_resource_conf({"ingress": []}) == CheckResult.PASSED
    assert rule.evaluated_keys == []


@pytest.mark.parametrize("ingress", [["var.rules"], [{"protocol": ["tcp"], "cidr_blocks": [["0.0.0.0/0"]]}]])
def test_unresolved_inline_ingress(ingress: list[Any]) -> None:
    assert SecurityGroupUnrestrictedIngress3306().scan_resource_conf({"ingress": ingress}) == CheckResult.UNKNOWN


def test_runner() -> None:
    rule = SecurityGroupUnrestrictedIngress3306()
    directory = Path(__file__).parent / "example_SecurityGroupUnrestrictedIngress3306"
    report = Runner().run(root_folder=str(directory), runner_filter=RunnerFilter(checks=[rule.id]))
    assert {record.resource for record in report.failed_checks} == {
        "aws_security_group.public_mysql", "aws_security_group.self_then_public",
        "aws_security_group_rule.public_range", "aws_vpc_security_group_ingress_rule.public_ipv6",
        "aws_vpc_security_group_ingress_rule.all_protocols",
    }
    assert {record.resource for record in report.passed_checks} == {
        "aws_security_group.restricted_mysql", "aws_security_group.no_ingress",
        "aws_security_group_rule.outbound_control", "aws_vpc_security_group_ingress_rule.application_source",
        "aws_vpc_security_group_ingress_rule.web_only",
    }
    assert report.get_summary()["parsing_errors"] == 0
    assert report.get_summary()["skipped"] == 0
