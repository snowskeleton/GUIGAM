from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from typing import Optional
import uvicorn
from datetime import datetime, timedelta

from app.database import get_db, create_tables
from app.models import User, UserSession, SSOConfig, AuditLog, RoleMapping
from app.security import (
    verify_password, 
    get_password_hash, 
    create_access_token, 
    verify_token,
    generate_session_id,
    validate_password_strength,
    encryption_manager
)
from app.sso import get_sso_provider, create_or_update_sso_user, validate_sso_config, get_available_groups_for_admin
import secrets

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
async def main_page(request: Request, current_user: User = Depends(get_current_user)):
    """Main dashboard - requires authentication."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user
    })


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Login page."""
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
    if payload.get("action") != "change_password":
        if not current_password or not verify_password(current_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Update password
    user.hashed_password = get_password_hash(new_password)
    
    # Invalidate all existing sessions except current one
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
        
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie("access_token", access_token, httponly=True, secure=True, samesite="lax")
        return response
    
    return {"message": "Password changed successfully"}




@app.post("/auth/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Logout and invalidate session."""
    current_user = get_current_user(request, db)
    if current_user:
        # Invalidate all user sessions
        db.query(UserSession).filter(UserSession.user_id == current_user.id).update({"is_active": False})
        db.commit()
        
        log_audit_event(db, current_user.id, "logout", None, "User logged out", True)
    
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# SSO Configuration Routes (Admin Only)
@app.get("/admin/sso/setup", response_class=HTMLResponse)
async def sso_setup_page(request: Request, current_user: User = Depends(get_current_user)):
    """SSO setup page - admin only."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse("sso_setup.html", {
        "request": request,
        "user": current_user
    })


@app.get("/admin/sso/status")
async def sso_status(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current SSO configuration status."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    sso_config = db.query(SSOConfig).filter(
        SSOConfig.provider == "microsoft").first()

    if sso_config:
        return {
            "configured": True,
            "enabled": sso_config.is_enabled,
            "provider": sso_config.provider,
            "created_at": sso_config.created_at.isoformat()
        }

    return {"configured": False}


@app.post("/admin/sso/test")
async def test_sso_config(request: Request,
                          current_user: User = Depends(get_current_user),
                          client_id: str = Form(...),
                          client_secret: str = Form(...),
                          tenant_id: str = Form(...),
                          redirect_uri: str = Form(...)):
    """Test SSO configuration."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        is_valid = validate_sso_config(
            client_id, client_secret, tenant_id, redirect_uri)
        return {"valid": is_valid}
    except Exception as e:
        return {"valid": False, "error": str(e)}


@app.post("/admin/sso/configure")
async def configure_sso(request: Request,
                        current_user: User = Depends(get_current_user),
                        client_id: str = Form(...),
                        client_secret: str = Form(...),
                        tenant_id: str = Form(...),
                        redirect_uri: str = Form(...),
                        enable_sso: bool = Form(False),
                        db: Session = Depends(get_db)):
    """Save SSO configuration."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        # Validate configuration first
        if not validate_sso_config(client_id, client_secret, tenant_id, redirect_uri):
            raise HTTPException(
                status_code=400, detail="Invalid SSO configuration")

        # Encrypt client secret
        encrypted_secret = encryption_manager.encrypt(client_secret)

        # Check if config exists
        sso_config = db.query(SSOConfig).filter(
            SSOConfig.provider == "microsoft").first()

        if sso_config:
            # Update existing
            sso_config.client_id = client_id
            sso_config.client_secret = encrypted_secret
            sso_config.tenant_id = tenant_id
            sso_config.redirect_uri = redirect_uri
            sso_config.is_enabled = enable_sso
            sso_config.updated_at = datetime.utcnow()
        else:
            # Create new
            sso_config = SSOConfig(
                provider="microsoft",
                client_id=client_id,
                client_secret=encrypted_secret,
                tenant_id=tenant_id,
                redirect_uri=redirect_uri,
                is_enabled=enable_sso
            )
            db.add(sso_config)

        db.commit()

        log_audit_event(db, current_user.id, "sso_configured", "microsoft",
                        f"SSO {'enabled' if enable_sso else 'configured'}", True, request.client.host)

        return {"message": "SSO configuration saved successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, detail=f"Failed to save configuration: {str(e)}")


@app.get("/admin/sso/groups")
async def get_azure_groups(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get available Azure groups for role mapping."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        # Get SSO configuration
        sso_config = db.query(SSOConfig).filter(
            SSOConfig.provider == "microsoft",
            SSOConfig.is_enabled == True
        ).first()

        if not sso_config:
            return {"groups": [], "error": "SSO not configured or disabled"}

        # Get groups using app-only permissions
        groups = get_available_groups_for_admin(sso_config)
        return {"groups": groups}

    except Exception as e:
        return {"groups": [], "error": str(e)}


@app.get("/admin/sso/role-mappings")
async def get_role_mappings(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current role mappings."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    mappings = db.query(RoleMapping).all()
    return {
        "mappings": [
            {
                "id": mapping.id,
                "azure_group_id": mapping.azure_group_id,
                "azure_group_name": mapping.azure_group_name,
                "guigam_role": mapping.guigam_role,
                "created_at": mapping.created_at.isoformat()
            }
            for mapping in mappings
        ]
    }


@app.post("/admin/sso/role-mappings")
async def create_role_mapping(request: Request,
                              current_user: User = Depends(get_current_user),
                              azure_group_id: str = Form(...),
                              azure_group_name: str = Form(...),
                              guigam_role: str = Form(...),
                              db: Session = Depends(get_db)):
    """Create or update role mapping."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if guigam_role not in ["user", "admin"]:
        raise HTTPException(
            status_code=400, detail="Invalid role. Must be 'user' or 'admin'")

    try:
        # Check if mapping already exists
        existing = db.query(RoleMapping).filter(
            RoleMapping.azure_group_id == azure_group_id).first()

        if existing:
            existing.azure_group_name = azure_group_name
            existing.guigam_role = guigam_role
            existing.updated_at = datetime.utcnow()
        else:
            mapping = RoleMapping(
                azure_group_id=azure_group_id,
                azure_group_name=azure_group_name,
                guigam_role=guigam_role
            )
            db.add(mapping)

        db.commit()

        log_audit_event(db, current_user.id, "role_mapping_updated", azure_group_name,
                        f"Mapped to role: {guigam_role}", True, request.client.host)

        return {"message": "Role mapping saved successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, detail=f"Failed to save role mapping: {str(e)}")


@app.delete("/admin/sso/role-mappings/{mapping_id}")
async def delete_role_mapping(mapping_id: int,
                              request: Request,
                              current_user: User = Depends(get_current_user),
                              db: Session = Depends(get_db)):
    """Delete a role mapping."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    mapping = db.query(RoleMapping).filter(
        RoleMapping.id == mapping_id).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="Role mapping not found")

    try:
        group_name = mapping.azure_group_name
        db.delete(mapping)
        db.commit()

        log_audit_event(db, current_user.id, "role_mapping_deleted", group_name,
                        "Role mapping removed", True, request.client.host)

        return {"message": "Role mapping deleted successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, detail=f"Failed to delete role mapping: {str(e)}")


# SSO Authentication Routes
@app.get("/auth/sso/microsoft")
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


@app.get("/auth/callback")
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


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
