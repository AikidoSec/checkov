from __future__ import annotations

from typing import Any

from checkov.arm.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.util.type_forcers import force_int


class StorageAccountDisablePublicAccess(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure that Storage accounts disallow public access"
        id = "CKV_AZURE_59"
        supported_resources = ("Microsoft.Storage/storageAccounts",)
        categories = (CheckCategories.NETWORKING,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "apiVersion" in conf:
            # Fail if apiVersion < 2017 as you could not set networkAcls
            year = force_int(conf["apiVersion"][0:4])

            if year is None:
                return CheckResult.UNKNOWN
            elif year < 2017:
                return CheckResult.FAILED

        if "properties" in conf:
            # Default value is 'Enabled', so let's check if the user explictly disabled it.
            if "publicNetworkAccess" in conf["properties"]:
                if conf["properties"]["publicNetworkAccess"] == "Disabled":
                    return CheckResult.PASSED

            if "networkAcls" in conf["properties"]:
                if not isinstance(conf["properties"]["networkAcls"], dict):
                    return CheckResult.FAILED
                
                # The endpoint is still reachable from public internet (as in, responds to DNS queries), however, access is disabled by the firewall.
                if "defaultAction" in conf["properties"]["networkAcls"]:
                    if conf["properties"]["networkAcls"]["defaultAction"] == "Deny":
                        return CheckResult.PASSED
                    
        return CheckResult.PASSED


check = StorageAccountDisablePublicAccess()
