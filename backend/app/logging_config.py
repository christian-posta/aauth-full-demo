"""Central logging levels for the backend process.

When ``DEBUG`` is true, the ``app`` tree and root use ``DEBUG``. When false, ``LOG_LEVEL``
(default **INFO**) applies to both root and ``app`` so startup logs (e.g. stable / ephemeral
JWK from the Agent Server client) are visible without ``DEBUG=true``.

AAuth-related **Python logging** (library + ``aauth.tokens`` in app code) is controlled by:

- ``AAUTH_LOG_LEVEL`` — if set to a valid level name, applies to both the ``aauth`` and
  ``aauth_signing`` logger trees (signing uses ``aauth_signing``, not ``aauth``).
- ``AAUTH_DEBUG`` — if ``AAUTH_LOG_LEVEL`` is unset, ``AAUTH_DEBUG=1`` (same truthiness as
  the aauth package) sets those two trees to ``logging.DEBUG``. This matches the common
  expectation of turning on AAuth verbosity in ``.env`` without remembering a second name.

The aauth repo also uses ``AAUTH_DEBUG`` for **print**-based traces in participant demos;
this backend only affects **loggers** here.

Third-party:

- ``A2A_LOG_LEVEL`` — ``a2a`` namespace (default: WARNING).
- ``HTTPX_LOG_LEVEL`` — ``httpx`` (default: WARNING).

Valid level names: DEBUG, INFO, WARNING, ERROR, CRITICAL, NOTSET (case-insensitive).
"""

from __future__ import annotations

import logging
import os

from app.config import settings

_LEVEL_NAMES = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "NOTSET"}
)


def _parse_log_level(env_name: str, default: int) -> int:
    raw = (os.getenv(env_name) or "").strip().upper()
    if not raw or raw not in _LEVEL_NAMES:
        return default
    return int(getattr(logging, raw))


def _is_aauth_debug_env() -> bool:
    """Match aauth.debug._is_debug_enabled truthiness for AAUTH_DEBUG."""
    value = os.environ.get("AAUTH_DEBUG", "0")
    return value.lower() not in ("0", "false", "no", "off", "")


def _resolve_aauth_library_log_level() -> int:
    """Level for ``aauth`` and ``aauth_signing`` loggers (signing is a separate namespace)."""
    raw = (os.getenv("AAUTH_LOG_LEVEL") or "").strip().upper()
    if raw in _LEVEL_NAMES:
        return int(getattr(logging, raw))
    if _is_aauth_debug_env():
        return logging.DEBUG
    return logging.INFO


def configure_logging() -> None:
    """Apply logger levels. Call once at process startup after ``load_dotenv()``."""
    if settings.debug:
        app_level = logging.DEBUG
    else:
        # Default INFO so Agent Server startup (stable / ephemeral keys) is visible; quiet with LOG_LEVEL=WARNING.
        app_level = _parse_log_level("LOG_LEVEL", logging.INFO)
    logging.getLogger("app").setLevel(app_level)
    # Root defaults to WARNING; align so ``app.*`` records can reach process handlers after propagation.
    root = logging.getLogger()
    if root.level == logging.NOTSET or root.level > app_level:
        root.setLevel(app_level)

    aauth_level = _resolve_aauth_library_log_level()
    logging.getLogger("aauth").setLevel(aauth_level)
    logging.getLogger("aauth_signing").setLevel(aauth_level)
    logging.getLogger("a2a").setLevel(
        _parse_log_level("A2A_LOG_LEVEL", logging.WARNING)
    )
    logging.getLogger("httpx").setLevel(
        _parse_log_level("HTTPX_LOG_LEVEL", logging.WARNING)
    )
