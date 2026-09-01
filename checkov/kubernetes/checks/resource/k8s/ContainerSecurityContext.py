from typing import Any, Dict

from checkov.common.models.enums import CheckResult
from checkov.kubernetes.checks.resource.base_container_check import BaseK8sContainerCheck


class ContainerSecurityContext(BaseK8sContainerCheck):
    def __init__(self) -> None:
        # CIS-1.5 5.7.3
        name = "Apply security context to your containers"
        # Location: container .securityContext
        id = "CKV_K8S_30"
        super().__init__(name=name, id=id, skip_windows_workloads=True)

    def scan_container_conf(self, metadata: Dict[str, Any], conf: Dict[str, Any]) -> CheckResult:
        self.evaluated_container_keys = ["securityContext"]
        if conf.get("securityContext"):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = ContainerSecurityContext()
