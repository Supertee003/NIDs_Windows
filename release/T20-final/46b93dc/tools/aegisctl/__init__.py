"""AEGIS NIDS Control Plane CLI (aegisctl)

Modular CLI for managing the AEGIS NIDS service.
"""
__version__ = "6.0.0"

# P0.3: Exit codes — every command must return one of these.
# 0 = command succeeded
# 1 = command failed (runtime error)
# 2 = invalid command / bad input
# 3 = authorization denied
# 4 = runtime unavailable (daemon not reachable)
# 5 = postcondition failed (command ran but result is invalid)
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_INVALID = 2
EXIT_AUTH_DENIED = 3
EXIT_RUNTIME_UNAVAILABLE = 4
EXIT_POSTCONDITION_FAILED = 5


def structured_error(code: int, error_code: str, message: str, state: str = "UNKNOWN") -> dict:
    """Return a structured error result dict."""
    return {
        "ok": False,
        "code": error_code,
        "state": state,
        "message": message,
    }


def structured_ok(data: dict, state: str = "OK") -> dict:
    """Return a structured success result dict."""
    return {
        "ok": True,
        "code": "OK",
        "state": state,
        "data": data,
    }
