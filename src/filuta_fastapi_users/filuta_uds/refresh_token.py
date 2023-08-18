import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Generic

from sqlalchemy import JSON, ForeignKey, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, declared_attr, mapped_column

from filuta_fastapi_users.authentication.strategy.db import AP, RefreshTokenDatabase
from filuta_fastapi_users.models import ID

from .generics import GUID, TIMESTAMPAware, now_utc


class SQLAlchemyBaseRefreshTokenTable(Generic[ID]):
    """Base SQLAlchemy refresh token table definition."""

    __tablename__ = "refresh_tokens"

    if TYPE_CHECKING:  # pragma: no cover
        token: str
        created_at: datetime
        scopes: str
        mfa_scopes: dict[str, int]
        user_id: ID
    else:
        token = mapped_column(String(length=43), primary_key=True)
        scopes = mapped_column(String(length=255))
        mfa_scopes = mapped_column(JSON())
        created_at = mapped_column(TIMESTAMPAware(timezone=True), index=True, nullable=False, default=now_utc)


class SQLAlchemyBaseRefreshTokenTableUUID(SQLAlchemyBaseRefreshTokenTable[uuid.UUID]):
    if TYPE_CHECKING:  # pragma: no cover
        user_id: uuid.UUID
    else:

        @declared_attr
        def user_id(cls) -> Mapped[GUID]:
            return mapped_column(GUID, ForeignKey("user.id", ondelete="cascade"), nullable=False)


class SQLAlchemyRefreshTokenDatabase(Generic[AP], RefreshTokenDatabase[AP]):
    """
    Refresh token database adapter for SQLAlchemy.

    :param session: SQLAlchemy session instance.
    :param refresh_token_table: SQLAlchemy refresh token model.
    """

    def __init__(
        self,
        session: AsyncSession,
        refresh_token_table: type[AP],
    ):
        self.session = session
        self.refresh_token_table = refresh_token_table

    async def get_by_token(self, token: str, max_age: datetime | None = None) -> AP | None:
        statement = select(self.refresh_token_table).where(self.refresh_token_table.token == token)
        if max_age is not None:
            statement = statement.where(self.refresh_token_table.created_at >= max_age)

        results = await self.session.execute(statement)
        return results.scalar_one_or_none()

    async def create(self, create_dict: dict[str, Any]) -> AP:
        refresh_token = self.refresh_token_table(**create_dict)
        self.session.add(refresh_token)
        await self.session.commit()
        await self.session.refresh(refresh_token)
        return refresh_token

    async def update(self, refresh_token: AP, update_dict: dict[str, Any]) -> AP:
        for key, value in update_dict.items():
            setattr(refresh_token, key, value)
        self.session.add(refresh_token)
        await self.session.commit()
        await self.session.refresh(refresh_token)
        return refresh_token

    async def delete(self, refresh_token: AP) -> None:
        await self.session.delete(refresh_token)
        await self.session.commit()
