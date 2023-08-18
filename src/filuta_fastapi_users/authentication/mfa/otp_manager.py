import secrets
from typing import Generic

from filuta_fastapi_users.authentication.strategy.db.adapter import OtpTokenDatabase
from filuta_fastapi_users.authentication.strategy.db.models import OTPTP
from filuta_fastapi_users.types import DependencyCallable


class OtpManager(Generic[OTPTP]):
    def __init__(
        self,
        otp_token_db: OtpTokenDatabase[OTPTP],
    ) -> None:
        self.otp_token_db = otp_token_db

    def generate_otp_token(self, length: int = 6) -> str:
        """Generate a random OTP of given length."""
        # Generate OTP using numbers 0-9
        otp = "".join([str(secrets.randbelow(10)) for _ in range(length)])
        return otp

    async def create_otp_email_token(self, access_token: str, mfa_token: str) -> OTPTP:
        otp_record = await self.otp_token_db.create(
            create_dict={"access_token": access_token, "mfa_type": "email", "mfa_token": mfa_token}
        )
        return otp_record

    async def find_otp_token(self, access_token: str, mfa_type: str, mfa_token: str) -> OTPTP | None:
        otp_record = await self.otp_token_db.find_otp_token(
            access_token=access_token, mfa_type=mfa_type, mfa_token=mfa_token
        )
        return otp_record


OtpManagerDependency = DependencyCallable[OtpManager[OTPTP]]
