from datetime import datetime
from typing import Any, Generic, Protocol

from filuta_fastapi_users.authentication.strategy.db import OTPTP
from filuta_fastapi_users.authentication.strategy.db.models import AP, RTP


class AccessTokenDatabase(Protocol, Generic[AP]):
    """Protocol for retrieving, creating and updating access tokens from a database."""

    async def get_by_token(self, token: str, max_age: datetime | None = None, authorized: bool = False) -> AP | None:
        """Get a single access token by token."""
        ...  # pragma: no cover

    async def create(self, create_dict: dict[str, Any]) -> AP:
        """Create an access token."""
        ...  # pragma: no cover

    async def update(self, access_token: AP, update_dict: dict[str, Any]) -> AP:
        """Update an access token."""
        ...  # pragma: no cover

    async def delete(self, access_token: AP) -> None:
        """Delete an access token."""
        ...  # pragma: no cover


class RefreshTokenDatabase(Protocol, Generic[RTP]):
    """Protocol for retrieving, creating and updating refresh tokens from a database."""

    async def get_by_token(self, token: str, max_age: datetime | None = None) -> RTP | None:
        """Get a single refresh token by token."""
        ...  # pragma: no cover

    async def create(self, create_dict: dict[str, Any]) -> RTP:
        """Create an refresh token."""
        ...  # pragma: no cover

    async def update(self, refresh_token: RTP, update_dict: dict[str, Any]) -> RTP:
        """Update an refresh token."""
        ...  # pragma: no cover

    async def delete(self, refresh_token: RTP) -> None:
        """Delete an refresh token."""
        ...  # pragma: no cover


class OtpTokenDatabase(Protocol, Generic[OTPTP]):
    """Protocol for retrieving, creating and updating OTP tokens from a database."""

    async def get_by_access_token(self, token: str, max_age: datetime | None = None) -> OTPTP | None:
        """Get a single OTP token by token."""
        ...  # pragma: no cover

    async def create(self, create_dict: dict[str, Any]) -> OTPTP:
        """Create an OTP token."""
        ...  # pragma: no cover

    async def update(self, otp_token: OTPTP, update_dict: dict[str, Any]) -> OTPTP:
        """Update an OTP token."""
        ...  # pragma: no cover

    async def delete(self, otp_record: OTPTP) -> None:
        """Delete an OTP token."""
        ...  # pragma: no cover

    async def find_otp_token(
        self, access_token: str, mfa_type: str, mfa_token: str, only_valid: bool = False
    ) -> OTPTP | None:
        """Finds an OTP token."""
        ...  # pragma: no cover

    async def user_has_token(self, access_token: str, mfa_type: str) -> OTPTP | None:
        """Checks whether an user has an OTP token"""
        ...  # pragma: no cover
