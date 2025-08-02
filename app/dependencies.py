"""
Authentication and authorization dependencies for FastAPI routes.
"""
from fastapi import Depends, HTTPException, Request

from app.models import User
from app.utils import get_current_user

def require_auth(request: Request, current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency that requires user authentication.
    Returns the current user or raises 401.
    For API routes.
    """
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user

def require_auth_page(request: Request, current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency that requires user authentication.
    Returns the current user or redirects to login.
    For page routes that render HTML.
    """
    if not current_user:
        # For HTML pages, redirect to login instead of returning 401
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return current_user

def require_admin(current_user: User = Depends(require_auth)) -> User:
    """
    Dependency that requires admin authentication.
    Returns the current user or raises 403.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def require_admin_page(current_user: User = Depends(require_auth_page)) -> User:
    """
    Dependency that requires admin authentication for pages.
    Returns the current user, redirects to login if not authenticated, or raises 403 if not admin.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
