from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.util.type_forcers import force_int
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class SecurityGroupUnrestrictedIngress3306(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure security groups do not allow public ingress to MySQL port 3306",
            id="CKV_AWS_AIK_1",
            categories=(CheckCategories.NETWORKING,),
            supported_resources=(
                "aws_security_group",
                "aws_security_group_rule",
                "aws_vpc_security_group_ingress_rule",
            ),
        )

    @staticmethod
    def _values(value: Any) -> list[Any]:
        if isinstance(value, list):
            return [item for nested in value for item in SecurityGroupUnrestrictedIngress3306._values(nested)]
        return [value]

    @staticmethod
    def _scalar(conf: dict[str, Any], key: str) -> Any:
        values = SecurityGroupUnrestrictedIngress3306._values(conf.get(key, []))
        return values[0] if len(values) == 1 else None

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        self.evaluated_keys: list[str] = []
        if "type" in conf:
            rule_type = self._scalar(conf, "type")
            if rule_type == "egress":
                return CheckResult.PASSED
            if rule_type != "ingress":
                return CheckResult.UNKNOWN

        if "ingress" in conf:
            unknown = False
            for index, rule in enumerate(self._values(conf["ingress"])):
                if not isinstance(rule, dict):
                    unknown = True
                    continue
                result = self._scan_rule(rule)
                if result == CheckResult.FAILED:
                    self.evaluated_keys = [f"ingress/[{index}]/{key}" for key in self.evaluated_keys]
                    return result
                unknown = unknown or result == CheckResult.UNKNOWN
            self.evaluated_keys = []
            return CheckResult.UNKNOWN if unknown else CheckResult.PASSED

        # A security group without inline ingress allows no ingress by itself.
        if getattr(self, "entity_type", None) == "aws_security_group":
            return CheckResult.PASSED
        return self._scan_rule(conf)

    def _public_source(self, conf: dict[str, Any]) -> CheckResult:
        unknown = False
        has_source = False
        for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
            for cidr in self._values(conf.get(key, [])):
                if cidr is None:
                    continue
                has_source = True
                try:
                    network = ip_network(cidr, strict=False) if isinstance(cidr, str) else None
                except ValueError:
                    network = None
                if network is None:
                    unknown = True
                elif network.prefixlen == 0:
                    return CheckResult.FAILED

        # These are not explicit public CIDR sources. Do not let them mask a public CIDR above.
        for key in ("security_groups", "source_security_group_id", "referenced_security_group_id", "prefix_list_ids"):
            if any(self._values(conf.get(key, []))):
                has_source = True
        if self._scalar(conf, "self") is True:
            has_source = True

        if unknown or not has_source:
            return CheckResult.UNKNOWN
        return CheckResult.PASSED

    def _mysql_port(self, conf: dict[str, Any]) -> CheckResult:
        protocol = self._scalar(conf, "ip_protocol" if "ip_protocol" in conf else "protocol")
        if protocol is None:
            return CheckResult.UNKNOWN
        protocol = str(protocol).lower()
        if protocol == "-1":
            return CheckResult.FAILED
        if protocol not in ("tcp", "6"):
            # Known non-TCP protocols cannot expose a MySQL TCP listener.
            if protocol in ("udp", "icmp", "icmpv6") or protocol.isdecimal():
                return CheckResult.PASSED
            return CheckResult.UNKNOWN

        raw_from = self._scalar(conf, "from_port")
        raw_to = self._scalar(conf, "to_port")
        from_port = force_int(raw_from) if not isinstance(raw_from, (bool, float)) else None
        to_port = force_int(raw_to) if not isinstance(raw_to, (bool, float)) else None
        if from_port is None or to_port is None or not 0 <= from_port <= to_port <= 65535:
            return CheckResult.UNKNOWN
        return CheckResult.FAILED if from_port <= 3306 <= to_port else CheckResult.PASSED

    def _scan_rule(self, conf: dict[str, Any]) -> CheckResult:
        self.evaluated_keys = [
            key for key in (
                "protocol", "ip_protocol", "from_port", "to_port",
                "cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6",
            ) if key in conf
        ]
        source = self._public_source(conf)
        port = self._mysql_port(conf)
        if source == CheckResult.PASSED or port == CheckResult.PASSED:
            return CheckResult.PASSED
        if source == CheckResult.FAILED and port == CheckResult.FAILED:
            return CheckResult.FAILED
        return CheckResult.UNKNOWN


check = SecurityGroupUnrestrictedIngress3306()
