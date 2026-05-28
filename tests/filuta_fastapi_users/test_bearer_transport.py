from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from filuta_fastapi_users.authentication.transport.base import TransportLogoutNotSupportedError
from filuta_fastapi_users.authentication.transport.bearer import BearerTransport


@pytest.mark.parametrize("token_url", ["login", "auth/token"])
def test_bearer_transport_init(token_url: str) -> None:
    transport: BearerTransport[Any] = BearerTransport(token_url)
    assert transport.scheme is not None


@pytest.mark.anyio
async def test_get_login_response(bearer_transport: BearerTransport[Any]) -> None:
    mock_record = AsyncMock()
    mock_record.token = "tok123"
    mock_record.scopes = "read"
    mock_record.mfa_scopes = {}
    resp = await bearer_transport.get_login_response(mock_record, "rtok")
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_get_logout_response_raises(bearer_transport: BearerTransport[Any]) -> None:
    with pytest.raises(TransportLogoutNotSupportedError):
        await bearer_transport.get_logout_response()


def test_openapi_responses(bearer_transport: BearerTransport[Any]) -> None:
    login_resp = bearer_transport.get_openapi_login_responses_success()
    logout_resp = bearer_transport.get_openapi_logout_responses_success()
    assert 200 in login_resp
    assert logout_resp == {}
