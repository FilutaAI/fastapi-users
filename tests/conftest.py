from typing import Any

import pytest

from filuta_fastapi_users.authentication.transport.bearer import BearerTransport
from filuta_fastapi_users.password import PasswordHelper


@pytest.fixture()
def dummy_fixture() -> int:
    return 2


@pytest.fixture
def bearer_transport() -> BearerTransport[Any]:
    return BearerTransport("auth/jwt/login")


@pytest.fixture
def password_helper() -> PasswordHelper:
    return PasswordHelper()
