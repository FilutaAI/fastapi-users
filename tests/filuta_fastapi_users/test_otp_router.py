from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from filuta_fastapi_users.authentication import AuthenticationBackend, BearerTransport
from filuta_fastapi_users.router.otp_router import OtpResponse, get_otp_router


def test_otp_response_optional_fields_default_to_none() -> None:
    assert OtpResponse(status=True, message="E-mail was sent").model_dump() == {
        "status": True,
        "message": "E-mail was sent",
        "error": None,
        "access_token": None,
    }
    assert OtpResponse(status=False, error="no-token").error == "no-token"
    assert OtpResponse(status=True, message="Approved", access_token="token").access_token == "token"


class AccessTokenRecord:
    """Stands in for a SQLAlchemy access token row, which pydantic can't serialize."""

    def __init__(self) -> None:
        self.token = "abc"
        self.scopes = "none"
        self.mfa_scopes = {"email": 0}


class FakeStrategy:
    def __init__(self, record: AccessTokenRecord) -> None:
        self.record = record

    async def get_token_record(self, token: str) -> AccessTokenRecord:
        return self.record

    async def update_token(self, access_token: AccessTokenRecord, data: dict[str, Any]) -> AccessTokenRecord:
        for key, value in data.items():
            setattr(access_token, key, value)
        return access_token


class FakeOtpManager:
    async def find_otp_token(self, *args: Any, **kwargs: Any) -> object:
        return object()

    async def delete_record(self, otp_record: object) -> None:
        return None


class FakeAuthenticator:
    def current_user_token(self, **kwargs: Any) -> Any:
        async def dependency() -> tuple[object, str]:
            return object(), "abc"

        return dependency

    def current_user(self, **kwargs: Any) -> Any:
        async def dependency() -> object:
            return object()

        return dependency


@pytest.mark.asyncio
async def test_validate_token_returns_access_token_record_as_json() -> None:
    record = AccessTokenRecord()
    backend: Any = AuthenticationBackend(
        name="test", transport=BearerTransport(tokenUrl="login"), get_strategy=lambda: FakeStrategy(record)
    )
    app = FastAPI()
    app.include_router(
        get_otp_router(
            backend,
            get_user_manager=lambda: None,  # type: ignore[arg-type,return-value]
            get_otp_manager=lambda: FakeOtpManager(),  # type: ignore[arg-type,return-value]
            authenticator=FakeAuthenticator(),  # type: ignore[arg-type]
        )
    )

    response = TestClient(app).post("/otp/validate-token", json={"code": "123456", "type": "email"})

    assert response.status_code == 200
    assert response.json()["access_token"] == {"token": "abc", "scopes": "approved", "mfa_scopes": {"email": 1}}
