from dataclasses import dataclass
from typing import Optional
from aauth import (
    parse_aauth_header as _parse_aauth_header,
    build_auth_token_challenge as _build_auth_token_challenge,
)


@dataclass
class AAuthChallenge:
    require: str
    resource_token: Optional[str] = None
    auth_server: Optional[str] = None
    code: Optional[str] = None


def parse_aauth_header(header_value: str) -> AAuthChallenge:
    parsed = _parse_aauth_header(header_value)

    return AAuthChallenge(
        require=parsed.get("require"),
        resource_token=parsed.get("resource_token"),
        auth_server=parsed.get("auth_server"),
        code=parsed.get("code"),
    )


def format_auth_token_required(resource_token: str, auth_server: str) -> str:
    return _build_auth_token_challenge(resource_token=resource_token, auth_server=auth_server)
