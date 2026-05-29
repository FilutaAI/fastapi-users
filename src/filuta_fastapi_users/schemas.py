from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr

SCHEMA = TypeVar("SCHEMA", bound=BaseModel)


class CreateUpdateDictModel(BaseModel):
    def create_update_dict(self) -> dict[str, Any]:
        return self.model_dump(
            exclude_unset=True,
            exclude={
                "id",
                "is_superuser",
                "is_poweruser",
                "is_active",
                "is_verified",
                "oauth_accounts",
            },
        )

    def create_update_dict_superuser(self) -> dict[str, Any]:
        return self.model_dump(exclude_unset=True, exclude={"id"})


class BaseUser(CreateUpdateDictModel):
    """Base User model."""

    id: Any
    email: EmailStr
    is_active: bool = True
    is_superuser: bool = False
    is_poweruser: bool = False
    is_verified: bool = False

    model_config = ConfigDict(from_attributes=True)


class BaseUserCreate(CreateUpdateDictModel):
    email: EmailStr
    password: str
    is_active: bool | None = True
    is_superuser: bool | None = False
    is_poweruser: bool | None = False
    is_verified: bool | None = False


class BaseUserUpdate(CreateUpdateDictModel):
    password: str | None = None
    email: EmailStr | None = None
    is_active: bool | None = None
    is_superuser: bool | None = None
    is_poweruser: bool | None = None
    is_verified: bool | None = None


U = TypeVar("U", bound=BaseUser)
UC = TypeVar("UC", bound=BaseUserCreate)
UU = TypeVar("UU", bound=BaseUserUpdate)


class BaseOAuthAccount(BaseModel):
    """Base OAuth account model."""

    id: Any
    oauth_name: str
    access_token: str
    expires_at: int | None = None
    refresh_token: str | None = None
    account_id: str
    account_email: str

    model_config = ConfigDict(from_attributes=True)


class BaseOAuthAccountMixin(BaseModel):
    """Adds OAuth accounts list to a User model."""

    oauth_accounts: list[BaseOAuthAccount] = []


class ValidateLoginRequestBody(BaseModel):
    username: str
    password: str
