import pytest

from filuta_fastapi_users import exceptions

EXCEPTION_CLASSES = [
    exceptions.FastAPIUsersException,
    exceptions.InvalidID,
    exceptions.UserAlreadyExists,
    exceptions.UserNotExists,
    exceptions.UserInactive,
    exceptions.UserAlreadyVerified,
    exceptions.InvalidVerifyToken,
    exceptions.InvalidResetPasswordToken,
]


@pytest.mark.parametrize("exc_class", EXCEPTION_CLASSES)
def test_exception_inheritance(exc_class: type[BaseException]) -> None:
    assert issubclass(exc_class, exceptions.FastAPIUsersException)
    assert issubclass(exc_class, Exception)


def test_invalid_password_exception() -> None:
    exc = exceptions.InvalidPasswordException("weak")
    assert exc.reason == "weak"
    assert isinstance(exc, exceptions.FastAPIUsersException)
