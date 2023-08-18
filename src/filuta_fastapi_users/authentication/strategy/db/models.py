from datetime import datetime
from typing import Protocol, TypeVar

from filuta_fastapi_users import models


class AccessTokenProtocol(Protocol[models.ID]):
    """Access token protocol that ORM model should follow."""

    token: str
    user_id: models.ID
    created_at: datetime
    scopes: str
    mfa_scopes: dict[str, int]


AP = TypeVar("AP", bound=AccessTokenProtocol)  # type: ignore


class RefreshTokenProtocol(Protocol[models.ID]):
    """Refresh token protocol that ORM model should follow."""

    token: str
    user_id: models.ID
    created_at: datetime


RTP = TypeVar("RTP", bound=RefreshTokenProtocol)  # type: ignore


class OtpTokenProtocol(Protocol):
    """OTP token protocol that ORM model should follow."""

    access_token: str
    mfa_type: str
    mfa_token: str
    created_at: datetime
    expire_at: datetime


OTPTP = TypeVar("OTPTP", bound=OtpTokenProtocol)
