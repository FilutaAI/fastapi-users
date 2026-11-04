from filuta_fastapi_users.router.otp_router import OtpResponse


def test_otp_response_optional_fields_default_to_none() -> None:
    assert OtpResponse(status=True, message="E-mail was sent").model_dump() == {
        "status": True,
        "message": "E-mail was sent",
        "error": None,
        "access_token": None,
    }
    assert OtpResponse(status=False, error="no-token").error == "no-token"
    assert OtpResponse(status=True, message="Approved", access_token="token").access_token == "token"
