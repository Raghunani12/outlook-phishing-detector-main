import os

from fastapi import Request
from fastapi.responses import RedirectResponse


def check_password(candidate: str) -> bool:
    expected = os.getenv("ADMIN_PASSWORD", "")
    return bool(expected) and candidate == expected


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("admin_authenticated"))


def require_admin(request: Request):
    """
    Dependency-style guard. Call at the top of a protected route:

        redirect = require_admin(request)
        if redirect:
            return redirect

    Returns a RedirectResponse to /admin/login if not authenticated, else None.
    Implemented this way (rather than raising HTTPException) so unauthenticated
    users land on a friendly login page instead of a raw 401 JSON error.
    """
    if not is_authenticated(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    return None
