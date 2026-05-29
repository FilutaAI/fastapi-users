from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from filuta_fastapi_users.jwt import (
    JWT_ALGORITHM,
    _get_secret_value,
    decode_jwt,
    generate_jwt,
)


@pytest.mark.parametrize(
    "secret,expected",
    [
        ("plain-secret", "plain-secret"),
        (SecretStr("secret-value"), "secret-value"),
    ],
)
def test_get_secret_value(secret: str | SecretStr, expected: str) -> None:
    assert _get_secret_value(secret) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"sub": "123", "aud": "test"},
        {"sub": "456", "aud": ["test"]},
    ],
)
def test_generate_jwt_no_lifetime(payload: dict[str, Any]) -> None:
    token = generate_jwt(payload, "secret")
    aud = payload["aud"] if isinstance(payload["aud"], list) else [payload["aud"]]
    decoded = decode_jwt(token, "secret", audience=aud)
    assert decoded["sub"] == payload["sub"]
    assert "exp" not in decoded


def test_generate_jwt_with_lifetime() -> None:
    token = generate_jwt({"sub": "123", "aud": "test"}, "secret", lifetime_seconds=3600)
    decoded = decode_jwt(token, "secret", audience=["test"])
    assert "exp" in decoded
    assert isinstance(decoded["exp"], int)


@pytest.mark.parametrize("algorithm", [JWT_ALGORITHM, "HS512"])
def test_generate_jwt_different_algorithms(algorithm: str) -> None:
    token = generate_jwt({"sub": "123", "aud": "test"}, "secret", algorithm=algorithm)
    decoded = decode_jwt(token, "secret", audience=["test"], algorithms=[algorithm])
    assert decoded["sub"] == "123"
