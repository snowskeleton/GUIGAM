from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from app.database import get_db
from app.models import User, UserSession
from app.security import (
    verify_password, 
    get_password_hash, 
    create_access_token,
    generate_session_id,
    validate_password_strength
)
from app.sso import get_sso_provider, create_or_update_sso_user
from app.utils import log_audit_event, get_current_user

router = APIRouter()

@router.post("/login")
async def login(request: Request, 
               username: str = Form(...), 
               password: str = Form(...),
               db: Session = Depends(get_db)):
    """Handle username/password login."""
    client_ip = request.client.host
    
    # Find user
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        log_audit_event(db, None, "login_failed", username, f"Invalid credentials", False, client_ip)
        raise HTTPException(status_code=400, detail="Invalid username or password")

    # Create session
    session_id = generate_session_id()
    expires_at = datetime.utcnow() + timedelta(hours=8)  # 8 hour session
    
    session = UserSession(
        session_id=session_id,
        user_id=user.id,
        expires_at=expires_at,
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent")
    )
    db.add(session)
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create access token
    token_data = {"sub": str(user.id), "session_id": session_id}
    access_token = create_access_token(token_data, expires_delta=timedelta(hours=8))
    
    log_audit_event(db, user.id, "login_success", None, "Username/password login", True, client_ip)
    
    # Redirect to dashboard
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie("access_token", access_token, httponly=True, secure=True, samesite="lax")
    return response


@router.post("/change-password")
async def change_password(request: Request,
                         current_password: str = Form(...),
                         new_password: str = Form(...),
                         current_user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    """Change user password."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify current password
    if not current_user.hashed_password or not verify_password(current_password, current_user.hashed_password):
        log_audit_event(db, current_user.id, "password_change_failed", None, 
                       "Invalid current password", False, request.client.host)
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Validate new password strength
    if not validate_password_strength(new_password):
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character"
        )

    # Update password
    current_user.hashed_password = get_password_hash(new_password)
    
    # Invalidate all other sessions for this user (keep current session)
    current_session_id = request.cookies.get("session_id")  # This might not work as expected
    if current_session_id:
        db.query(UserSession).filter(
            UserSession.user_id == current_user.id,
            UserSession.session_id != current_session_id
        ).delete()
    
    db.commit()

    log_audit_event(db, current_user.id, "password_changed", None, 
                   "Password changed successfully", True, request.client.host)

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(request: Request, 
                current_user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """Handle user logout."""
    if current_user:
        # Invalidate current session
        token = request.cookies.get("access_token")
        if token:
            from app.security import verify_token
            payload = verify_token(token)
            if payload:
                session_id = payload.get("session_id")
                if session_id:
                    session = db.query(UserSession).filter(
                        UserSession.session_id == session_id
                    ).first()
                    if session:
                        session.is_active = False
                        db.commit()

        log_audit_event(db, current_user.id, "logout", None, 
                       "User logged out", True, request.client.host)

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# SSO Authentication Routes
@router.get("/sso/microsoft")
async def microsoft_sso_login(request: Request, db: Session = Depends(get_db)):
    """Initiate Microsoft SSO login."""
    sso_provider = get_sso_provider("microsoft", db)
    if not sso_provider:
        raise HTTPException(
            status_code=400, detail="Microsoft SSO not configured")

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Store state in session (you might want to use Redis for this)
    auth_url = sso_provider.get_auth_url(state)

    # For simplicity, we'll store state in a cookie temporarily
    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie("sso_state", state, httponly=True,
                        max_age=600)  # 10 minute expiry

    return response


@router.get("/callback")
async def sso_callback(request: Request,
                       code: str = None,
                       state: str = None,
                       error: str = None,
                       db: Session = Depends(get_db)):
    """Handle SSO callback."""
    if error:
        log_audit_event(db, None, "sso_error", "microsoft",
                        f"SSO error: {error}", False, request.client.host)
        raise HTTPException(status_code=400, detail=f"SSO error: {error}")

    if not code or not state:
        raise HTTPException(
            status_code=400, detail="Missing authorization code or state")

    # Verify state (CSRF protection)
    stored_state = request.cookies.get("sso_state")
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    # Get SSO provider
    sso_provider = get_sso_provider("microsoft", db)
    if not sso_provider:
        raise HTTPException(
            status_code=400, detail="Microsoft SSO not configured")

    # Handle callback
    sso_result = sso_provider.handle_callback(code, state)
    if not sso_result:
        log_audit_event(db, None, "sso_callback_failed", "microsoft",
                        "Failed to process callback", False, request.client.host)
        raise HTTPException(
            status_code=400, detail="Failed to authenticate with Microsoft")

    # Create or update user
    user = create_or_update_sso_user(
        sso_result["user_info"], sso_result["groups"], db)
    if not user:
        log_audit_event(db, None, "sso_user_creation_failed", "microsoft",
                        "Failed to create user", False, request.client.host)
        raise HTTPException(
            status_code=400, detail="Failed to create user account")

    # Create session
    session_id = generate_session_id()
    expires_at = datetime.utcnow() + timedelta(hours=8)

    session = UserSession(
        session_id=session_id,
        user_id=user.id,
        expires_at=expires_at,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    db.add(session)

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Create access token
    token_data = {"sub": str(user.id), "session_id": session_id}
    access_token = create_access_token(
        token_data, expires_delta=timedelta(hours=8))

    log_audit_event(db, user.id, "sso_login_success", "microsoft",
                    "SSO login successful", True, request.client.host)

    # Redirect to dashboard
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie("access_token", access_token,
                        httponly=True, secure=True, samesite="lax")
    response.delete_cookie("sso_state")  # Clean up state cookie

    return response