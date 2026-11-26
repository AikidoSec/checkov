from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import Mock

import aioresponses.core
import pytest
from aiohttp import ClientResponse

from checkov.common.bridgecrew.bc_source import SourceType
from checkov.common.bridgecrew.platform_integration import BcPlatformIntegration, bc_integration


# aiohttp>=3.14 requires a `stream_writer` argument that aioresponses (<=0.7.9) doesn't pass
if "stream_writer" in inspect.signature(ClientResponse.__init__).parameters:

    class _AioresponsesClientResponse(ClientResponse):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.setdefault("stream_writer", Mock(output_size=0))
            super().__init__(*args, **kwargs)

    aioresponses.core.ClientResponse = _AioresponsesClientResponse  # type: ignore[misc]


@pytest.fixture()
def mock_bc_integration() -> BcPlatformIntegration:
    bc_integration.bc_api_key = "abcd1234-abcd-1234-abcd-1234abcd1234"
    bc_integration.setup_bridgecrew_credentials(
        repo_id="bridgecrewio/checkov",
        skip_fixes=True,
        skip_download=True,
        source=SourceType("Github", False),
        source_version="1.0",
        repo_branch="master",
    )
    return bc_integration
