import secrets
from datetime import datetime, timedelta
from typing import Generic

from filuta_fastapi_users import models
from filuta_fastapi_users.authentication.strategy.db.adapter import RefreshTokenDatabase
from filuta_fastapi_users.authentication.strategy.db.models import RTP
from filuta_fastapi_users.types import DependencyCallable


class RefreshTokenManager(Generic[RTP]):
    def __init__(
        self,
        refresh_token_db: RefreshTokenDatabase[RTP],
    ) -> None:
        self.refresh_token_db = refresh_token_db

    def generate_refresh_token(self, length: int = 100) -> str:
        """Generate a random refresh token of given length."""
        return secrets.token_urlsafe(length)

    async def create_refresh_token(self, token: str, user: models.UP) -> RTP:
        current_datetime = datetime.utcnow()
        expire_time = current_datetime + timedelta(days=30)

        return await self.refresh_token_db.create(
            create_dict={"token": token, "user_id": user.id, "created_at": current_datetime, "expire_time": expire_time}
        )

    async def update_refresh_token(self, refresh_token_record: RTP, token: str) -> RTP:
        return await self.refresh_token_db.update(refresh_token=refresh_token_record, update_dict={"token": token})

    async def delete_record(self, item: RTP) -> None:
        return await self.refresh_token_db.delete(refresh_token=item)


RefreshTokenManagerDependency = DependencyCallable[RefreshTokenManager[RTP]]
