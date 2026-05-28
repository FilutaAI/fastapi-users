from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from sqlalchemy import String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from filuta_fastapi_users.authentication import OtpTokenDatabase

from .generics import TIMESTAMPAware, now_utc


class SQLAlchemyBaseOtpTokenTable[ID]:
    """Base SQLAlchemy access token table definition."""

    __tablename__ = "otp_tokens"

    if TYPE_CHECKING:  # pragma: no cover
        access_token: ClassVar[str]
        mfa_type: ClassVar[str]
        mfa_token: ClassVar[str]
        created_at: ClassVar[datetime]
        expire_at: ClassVar[datetime]
    else:
        access_token: Mapped[str] = mapped_column(String(length=43), primary_key=True)
        mfa_type: Mapped[str] = mapped_column(String(length=43), primary_key=True)
        mfa_token: Mapped[str] = mapped_column(String(length=43), primary_key=True)
        created_at: Mapped[datetime] = mapped_column(
            TIMESTAMPAware(timezone=True), index=True, nullable=False, default=now_utc
        )
        expire_at: Mapped[datetime] = mapped_column(
            TIMESTAMPAware(timezone=True), index=True, nullable=False, default=now_utc
        )


class SQLAlchemyOtpTokenDatabase[OTPTP](OtpTokenDatabase[OTPTP]):
    """
    OTP token database adapter for SQLAlchemy.

    :param session: SQLAlchemy session instance.
    :param otp_token_table: SQLAlchemy OTP token model.
    """

    def __init__(
        self,
        session: AsyncSession,
        otp_token_table: type[OTPTP],
    ):
        self.session = session
        self.otp_token_table = otp_token_table

    async def get_by_access_token(self, access_token: str, max_age: datetime | None = None) -> OTPTP | None:
        statement = select(self.otp_token_table).where(self.otp_token_table.access_token == access_token)  # type: ignore[attr-defined]
        if max_age is not None:
            statement = statement.where(self.otp_token_table.created_at >= max_age)  # type: ignore[attr-defined]

        results = await self.session.execute(statement)
        return results.scalar_one_or_none()

    async def find_otp_token(
        self, access_token: str, mfa_type: str, mfa_token: str, only_valid: bool = False
    ) -> OTPTP | None:
        statement = (
            select(self.otp_token_table)
            .where(self.otp_token_table.access_token == access_token)  # type: ignore[attr-defined]
            .where(self.otp_token_table.mfa_token == mfa_token)  # type: ignore[attr-defined]
            .where(self.otp_token_table.mfa_type == mfa_type)  # type: ignore[attr-defined]
        )

        if only_valid:
            current_utc_time = datetime.utcnow()
            statement = statement.where(self.otp_token_table.expire_at > current_utc_time)  # type: ignore[attr-defined]

        results = await self.session.execute(statement)
        return results.scalar_one_or_none()

    async def user_has_token(self, access_token: str, mfa_type: str) -> OTPTP | None:
        statement = (
            select(self.otp_token_table)
            .where(self.otp_token_table.access_token == access_token)  # type: ignore[attr-defined]
            .where(self.otp_token_table.mfa_type == mfa_type)  # type: ignore[attr-defined]
        )

        results = await self.session.execute(statement)
        return results.scalar_one_or_none()

    async def create(self, create_dict: dict[str, Any]) -> OTPTP:
        otp_token = self.otp_token_table(**create_dict)
        self.session.add(otp_token)
        await self.session.commit()
        await self.session.refresh(otp_token)
        return otp_token

    async def update(self, otp_token: OTPTP, update_dict: dict[str, Any]) -> OTPTP:
        for key, value in update_dict.items():
            setattr(otp_token, key, value)
        self.session.add(otp_token)
        await self.session.commit()
        await self.session.refresh(otp_token)
        return otp_token

    async def delete(self, otp_token: OTPTP) -> None:
        await self.session.delete(otp_token)
        await self.session.commit()
