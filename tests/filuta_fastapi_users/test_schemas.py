from typing import Any

import pytest

from filuta_fastapi_users.schemas import (
    BaseUserCreate,
    BaseUserUpdate,
    CreateUpdateDictModel,
)


def test_create_update_dict_excludes_fields() -> None:
    user_create = BaseUserCreate(email="test@example.com", password="pass")
    update_dict = user_create.create_update_dict()
    assert "id" not in update_dict
    assert "is_superuser" not in update_dict
    assert update_dict["email"] == "test@example.com"


def test_create_update_dict_superuser() -> None:
    user_update = BaseUserUpdate(email="new@example.com")
    update_dict = user_update.create_update_dict_superuser()
    assert "id" not in update_dict
    assert update_dict["email"] == "new@example.com"


model_classes: list[type[CreateUpdateDictModel]] = [BaseUserCreate, BaseUserUpdate]


@pytest.mark.parametrize("model_class", model_classes)
def test_model_instantiation(model_class: type[Any]) -> None:
    if model_class is BaseUserCreate:
        instance: Any = model_class(email="a@b.com", password="p")
    else:
        instance = model_class(email="a@b.com")
    assert instance is not None
