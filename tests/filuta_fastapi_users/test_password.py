"""Tests for password hashing, verification, and automatic bcrypt -> argon2 migration."""

from pwdlib.hashers.bcrypt import BcryptHasher

from filuta_fastapi_users.password import PasswordHelper


def test_password_helper_hash_uses_argon2(password_helper: PasswordHelper) -> None:
    """New passwords and changed passwords must use argon2 (first hasher)."""
    hashed = password_helper.hash("test-password-123")
    assert hashed.startswith("$argon2")


def test_password_helper_generate_token(password_helper: PasswordHelper) -> None:
    """Token generation uses secrets.token_urlsafe(32)."""
    token = password_helper.generate()
    assert len(token) > 40  # urlsafe base64 of 32 bytes is ~43 chars


def test_password_helper_verify_and_update_migrates_bcrypt(password_helper: PasswordHelper) -> None:
    """Login with legacy bcrypt hash succeeds and returns argon2 update hash."""
    # Simulate legacy bcrypt hash (as would exist for old users)
    bcrypt_hasher = BcryptHasher()
    legacy_hash = bcrypt_hasher.hash("legacy-pass")

    verified, new_hash = password_helper.verify_and_update("legacy-pass", legacy_hash)

    assert verified is True
    assert new_hash is not None
    assert new_hash.startswith("$argon2")


def test_password_helper_verify_and_update_no_update_for_argon2(password_helper: PasswordHelper) -> None:
    """Subsequent logins with argon2 hash do not trigger an update."""
    argon2_hash = password_helper.hash("fresh-pass")

    verified, new_hash = password_helper.verify_and_update("fresh-pass", argon2_hash)

    assert verified is True
    assert new_hash is None
