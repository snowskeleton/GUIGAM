from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
import uvicorn
from datetime import datetime, timedelta

from app.database import get_db, create_tables
from app.models import User, UserSession, SSOConfig, AuditLog
from app.security import (
    verify_password, 
    get_password_hash, 
    create_access_token, 
    verify_token,
    generate_session_id,
    validate_password_strength
)

app = FastAPI(title="GAM Web Interface", version="1.0.0")

# Setup templates and static files
templates = Jinja2Templates(directory="app/templates")

# Security
security = HTTPBearer(auto_error=False)


def log_audit_event(db: Session, user_id: Optional[int], action: str, 
                   resource: str = None, details: str = None, 
                   success: bool = True, ip_address: str = None):
    """Log audit events."""
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        success=success,
        ip_address=ip_address
    )
    db.add(log_entry)
    db.commit()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Get current authenticated user."""
    # Get token from cookie
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    payload = verify_token(token)
    if not payload:
        return None
    
    user_id = payload.get("sub")
    if not user_id:
        return None
    
    # Verify session is still active
    session_id = payload.get("session_id")
    if session_id:
        session = db.query(UserSession).filter(
            UserSession.session_id == session_id,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()
        if not session:
            return None
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    return user


@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    create_tables()


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Main login page."""
    # Check if SSO is configured
    sso_config = db.query(SSOConfig).filter(
        SSOConfig.provider == "microsoft",
        SSOConfig.is_enabled == True
    ).first()
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "sso_enabled": sso_config is not None
    })


@app.post("/auth/login")
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
    
    # Check if first login
    if user.is_first_login:
        # Create temporary session for password change
        session_id = generate_session_id()
        expires_at = datetime.utcnow() + timedelta(minutes=15)  # Short expiry for password change
        
        session = UserSession(
            session_id=session_id,
            user_id=user.id,
            expires_at=expires_at,
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent")
        )
        db.add(session)
        db.commit()
        
        # Create token for password change
        token_data = {"sub": str(user.id), "session_id": session_id, "action": "change_password"}
        token = create_access_token(token_data, expires_delta=timedelta(minutes=15))
        
        log_audit_event(db, user.id, "first_login", None, "Redirecting to password change", True, client_ip)
        
        response = templates.TemplateResponse("change_password.html", {
            "request": request,
            "token": token,
            "first_login": True
        })
        return response
    
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
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie("access_token", access_token, httponly=True, secure=True, samesite="lax")
    return response


@app.post("/auth/change-password")
async def change_password(request: Request,
                         current_password: str = Form(None),
                         new_password: str = Form(...),
                         confirm_password: str = Form(...),
                         token: str = Form(...),
                         db: Session = Depends(get_db)):
    """Handle password change for first-time login or regular password change."""
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    if not validate_password_strength(new_password):
        raise HTTPException(status_code=400, detail="Password does not meet requirements")
    
    # Verify token
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # For non-first login, verify current password
    if not user.is_first_login and payload.get("action") != "change_password":
        if not current_password or not verify_password(current_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Update password
    user.hashed_password = get_password_hash(new_password)
    user.is_first_login = False
    
    # Invalidate all existing sessions except current one if it's a regular password change
    if not user.is_first_login:
        session_id = payload.get("session_id")
        db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.session_id != session_id
        ).update({"is_active": False})
    
    db.commit()
    
    log_audit_event(db, user.id, "password_changed", None, "Password updated", True, request.client.host)
    
    # If first login, create new session and redirect to dashboard
    if payload.get("action") == "change_password":
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
        db.commit()
        
        token_data = {"sub": str(user.id), "session_id": session_id}
        access_token = create_access_token(token_data, expires_delta=timedelta(hours=8))
        
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie("access_token", access_token, httponly=True, secure=True, samesite="lax")
        return response
    
    return {"message": "Password changed successfully"}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: User = Depends(get_current_user)):
    """Main dashboard - requires authentication."""
    if not current_user:
        return RedirectResponse(url="/", status_code=302)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user
    })


@app.post("/auth/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Logout and invalidate session."""
    current_user = get_current_user(request, db)
    if current_user:
        # Invalidate all user sessions
        db.query(UserSession).filter(UserSession.user_id == current_user.id).update({"is_active": False})
        db.commit()
        
        log_audit_event(db, current_user.id, "logout", None, "User logged out", True)
    
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("access_token")
    return response


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)