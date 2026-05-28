from typing import Any, Protocol

from filuta_fastapi_users import models
from filuta_fastapi_users.manager import BaseUserManager


class StrategyDestroyNotSupportedError(Exception):
    pass


class Strategy[UP: "models.UserProtocol[Any]", ID, AP: "models.AccessTokenProtocol[Any]"](Protocol):
    async def read_token(
        self,
        token: str | None,
        user_manager: BaseUserManager[UP, ID],
        authorized: bool = False,
        ignore_expired: bool = False,
    ) -> UP | None: ...  # pragma: no cover

    async def update_token(self, access_token: AP, data: dict[str, Any]) -> AP: ...  # pragma: no cover

    async def get_token_record_raw(self, token: str | None) -> AP | None: ...  # pragma: no cover

    async def get_token_record(self, token: str | None) -> AP | None: ...  # pragma: no cover

    async def insert_token(self, access_token_dict: dict[str, Any]) -> AP: ...  # pragma: no cover

    async def write_token(self, user: UP) -> AP: ...  # pragma: no cover

    async def destroy_token(self, token: str) -> None: ...  # pragma: no cover

    def generate_token(self) -> str: ...  # pragma: no cover

    async def get_latest_token_for_user(self, user: UP) -> AP: ...  # pragma: no cover
