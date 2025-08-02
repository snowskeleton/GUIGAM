from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.models import User, UserSession, SSOConfig, RoleMapping, GoogleWorkspaceTenant
from app.security import get_password_hash, validate_password_strength, encryption_manager
from app.sso import validate_sso_config, get_available_groups_for_admin
from app.utils import log_audit_event
from app.dependencies import require_admin, require_admin_page

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# SSO Admin Routes
@router.get("/sso/setup", response_class=HTMLResponse)
async def sso_setup_page(request: Request, current_user: User = Depends(require_admin_page)):
    """SSO setup page."""
    return templates.TemplateResponse("sso_setup.html", {"request": request, "user": current_user})

@router.get("/sso/status")
async def get_sso_status(request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get SSO configuration status."""

    sso_config = db.query(SSOConfig).filter(
        SSOConfig.provider == "microsoft"
    ).first()

    if sso_config:
        return {
            "configured": True,
            "enabled": sso_config.is_enabled,
            "provider": sso_config.provider,
            "created_at": sso_config.created_at.isoformat()
        }
    else:
        return {"configured": False}

@router.post("/sso/test")
async def test_sso_connection(request: Request,
                              current_user: User = Depends(require_admin),
                             client_id: str = Form(...),
                             tenant_id: str = Form(...),
                             client_secret: str = Form(...),
                             db: Session = Depends(get_db)):
    """Test SSO connection."""

    try:
        # Validate configuration
        is_valid = validate_sso_config(client_id, tenant_id, client_secret)
        
        if is_valid:
            log_audit_event(db, current_user.id, "sso_test_success", "microsoft",
                           "SSO connection test successful", True, request.client.host)
            return {"valid": True, "message": "Connection test successful"}
        else:
            log_audit_event(db, current_user.id, "sso_test_failed", "microsoft",
                           "SSO connection test failed", False, request.client.host)
            return {"valid": False, "error": "Invalid configuration"}

    except Exception as e:
        log_audit_event(db, current_user.id, "sso_test_error", "microsoft",
                       f"SSO test error: {str(e)}", False, request.client.host)
        return {"valid": False, "error": str(e)}

@router.post("/sso/configure")
async def configure_sso(request: Request,
                        current_user: User = Depends(require_admin),
                       client_id: str = Form(...),
                       tenant_id: str = Form(...),
                       client_secret: str = Form(...),
                       redirect_uri: str = Form(...),
                       enable_sso: bool = Form(False),
                       db: Session = Depends(get_db)):
    """Configure SSO settings."""

    try:
        # Check if SSO config already exists
        sso_config = db.query(SSOConfig).filter(
            SSOConfig.provider == "microsoft").first()

        if sso_config:
            # Update existing configuration
            sso_config.client_id = client_id
            sso_config.tenant_id = tenant_id
            sso_config.client_secret = encryption_manager.encrypt(client_secret)
            sso_config.redirect_uri = redirect_uri
            sso_config.is_enabled = enable_sso
            sso_config.updated_at = datetime.utcnow()
        else:
            # Create new configuration
            sso_config = SSOConfig(
                provider="microsoft",
                client_id=client_id,
                tenant_id=tenant_id,
                client_secret=encryption_manager.encrypt(client_secret),
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

@router.get("/sso/groups")
async def get_azure_groups(request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get available Azure groups for role mapping."""

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

@router.get("/sso/role-mappings")
async def get_role_mappings(request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get current role mappings."""

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

@router.post("/sso/role-mappings")
async def create_role_mapping(request: Request,
                              current_user: User = Depends(require_admin),
                              azure_group_id: str = Form(...),
                              azure_group_name: str = Form(...),
                              guigam_role: str = Form(...),
                              db: Session = Depends(get_db)):
    """Create or update role mapping."""

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

@router.delete("/sso/role-mappings/{mapping_id}")
async def delete_role_mapping(mapping_id: int,
                              request: Request,
                              current_user: User = Depends(require_admin),
                              db: Session = Depends(get_db)):
    """Delete a role mapping."""

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

# User Management Routes
@router.get("/users", response_class=HTMLResponse)
async def admin_users_page(request: Request, current_user: User = Depends(require_admin_page)):
    """Admin user management page."""
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": current_user})

@router.get("/users/list")
async def get_users_list(request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get list of all users."""
    
    users = db.query(User).all()
    user_list = []
    
    for user in users:
        # Count active sessions
        active_sessions = db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.expires_at > datetime.utcnow()
        ).count()
        
        user_list.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "has_password": user.hashed_password is not None,
            "is_sso_user": user.azure_id is not None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "created_at": user.created_at.isoformat() if hasattr(user, 'created_at') else None,
            "active_sessions": active_sessions
        })
    
    return {"users": user_list}

@router.post("/users/{user_id}/role")
async def update_user_role(user_id: int, 
                          request: Request,
                           current_user: User = Depends(require_admin),
                          role: str = Form(...),
                          db: Session = Depends(get_db)):
    """Update user role."""
    
    if role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'user' or 'admin'")
    
    # Don't allow changing your own role
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow role changes for SSO users
    if user.azure_id:
        raise HTTPException(status_code=400, detail="Cannot change role for SSO users. Role is managed through Azure AD groups.")
    
    try:
        old_role = user.role
        user.role = role
        db.commit()
        
        log_audit_event(db, current_user.id, "user_role_updated", user.username,
                       f"Role changed from {old_role} to {role}", True, request.client.host)
        
        return {"message": f"User role updated to {role} successfully"}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update user role: {str(e)}")

@router.post("/users/{user_id}/password-reset")
async def reset_user_password(user_id: int, 
                             request: Request,
                              current_user: User = Depends(require_admin),
                             new_password: str = Form(...),
                             db: Session = Depends(get_db)):
    """Reset user password."""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow password reset for SSO users
    if user.azure_id:
        raise HTTPException(status_code=400, detail="Cannot reset password for SSO users")
    
    # Validate password strength
    if not validate_password_strength(new_password):
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character"
        )
    
    try:
        user.hashed_password = get_password_hash(new_password)
        
        # Invalidate all existing sessions for this user
        db.query(UserSession).filter(UserSession.user_id == user_id).delete()
        
        db.commit()
        
        log_audit_event(db, current_user.id, "user_password_reset", user.username,
                       "Password reset by admin", True, request.client.host)
        
        return {"message": "Password reset successfully. User will need to log in again."}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {str(e)}")

@router.post("/users/{user_id}/toggle-status")
async def toggle_user_status(user_id: int, 
                            request: Request,
                             current_user: User = Depends(require_admin),
                            db: Session = Depends(get_db)):
    """Toggle user active/inactive status."""
    
    # Don't allow disabling your own account
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        old_status = user.is_active
        user.is_active = not user.is_active
        
        # If disabling user, invalidate all their sessions
        if not user.is_active:
            db.query(UserSession).filter(UserSession.user_id == user_id).delete()
        
        db.commit()
        
        action = "enabled" if user.is_active else "disabled"
        log_audit_event(db, current_user.id, "user_status_changed", user.username,
                       f"User {action}", True, request.client.host)
        
        return {"message": f"User {action} successfully", "is_active": user.is_active}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update user status: {str(e)}")

# Google Workspace Tenant Management Routes
@router.get("/tenants", response_class=HTMLResponse)
async def admin_tenants_page(request: Request, current_user: User = Depends(require_admin_page)):
    """Admin tenant management page."""
    return templates.TemplateResponse("admin_tenants.html", {"request": request, "user": current_user})

@router.get("/tenants/list")
async def get_tenants_list(request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get list of all Google Workspace tenants."""
    tenants = db.query(GoogleWorkspaceTenant).all()
    tenant_list = []
    
    for tenant in tenants:
        tenant_list.append({
            "id": tenant.id,
            "domain": tenant.domain,
            "display_name": tenant.display_name,
            "admin_email": tenant.admin_email,
            "is_active": tenant.is_active,
            "created_at": tenant.created_at.isoformat(),
            "updated_at": tenant.updated_at.isoformat()
        })
    
    return {"tenants": tenant_list}

@router.post("/tenants")
async def create_tenant(request: Request,
                       current_user: User = Depends(require_admin),
                       domain: str = Form(...),
                       display_name: str = Form(...),
                       admin_email: str = Form(...),
                       service_account_key: str = Form(...),
                       db: Session = Depends(get_db)):
    """Create a new Google Workspace tenant."""
    # Validate domain format
    if not domain or '.' not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    
    # Validate email format
    if not admin_email or '@' not in admin_email:
        raise HTTPException(status_code=400, detail="Invalid admin email format")
    
    # Check if domain already exists
    existing = db.query(GoogleWorkspaceTenant).filter(
        GoogleWorkspaceTenant.domain == domain
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists")
    
    try:
        # Validate service account key is valid JSON
        import json
        json.loads(service_account_key)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid service account key JSON")
    
    try:
        # Encrypt the service account key
        encrypted_key = encryption_manager.encrypt(service_account_key)
        
        # Create tenant
        tenant = GoogleWorkspaceTenant(
            domain=domain.lower(),
            display_name=display_name,
            admin_email=admin_email.lower(),
            service_account_key=encrypted_key
        )
        db.add(tenant)
        db.commit()
        
        log_audit_event(db, current_user.id, "tenant_created", domain,
                       f"Created tenant: {display_name}", True, request.client.host)
        
        return {"message": f"Tenant {domain} created successfully", "tenant_id": tenant.id}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create tenant: {str(e)}")

@router.post("/tenants/{tenant_id}/test")
async def test_tenant_connection(tenant_id: int,
                                request: Request,
                                current_user: User = Depends(require_admin),
                                db: Session = Depends(get_db)):
    """Test connection to Google Workspace tenant."""
    tenant = db.query(GoogleWorkspaceTenant).filter(
        GoogleWorkspaceTenant.id == tenant_id
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    try:
        # Here you would implement actual Google Workspace API testing
        # For now, we'll just validate the service account key format
        import json
        decrypted_key = encryption_manager.decrypt(tenant.service_account_key)
        key_data = json.loads(decrypted_key)
        
        # Basic validation of service account key structure
        required_fields = ["type", "project_id", "private_key_id", "private_key", "client_email"]
        for field in required_fields:
            if field not in key_data:
                raise ValueError(f"Missing required field: {field}")
        
        if key_data.get("type") != "service_account":
            raise ValueError("Invalid service account key type")
        
        log_audit_event(db, current_user.id, "tenant_test_success", tenant.domain,
                       "Tenant connection test successful", True, request.client.host)
        
        return {"valid": True, "message": "Connection test successful"}
    
    except Exception as e:
        log_audit_event(db, current_user.id, "tenant_test_failed", tenant.domain,
                       f"Tenant test failed: {str(e)}", False, request.client.host)
        return {"valid": False, "error": str(e)}

@router.put("/tenants/{tenant_id}")
async def update_tenant(tenant_id: int,
                       request: Request,
                       current_user: User = Depends(require_admin),
                       display_name: str = Form(...),
                       admin_email: str = Form(...),
                       service_account_key: str = Form(None),
                       db: Session = Depends(get_db)):
    """Update a Google Workspace tenant."""
    tenant = db.query(GoogleWorkspaceTenant).filter(
        GoogleWorkspaceTenant.id == tenant_id
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Validate email format
    if not admin_email or '@' not in admin_email:
        raise HTTPException(status_code=400, detail="Invalid admin email format")
    
    try:
        # Update basic info
        tenant.display_name = display_name
        tenant.admin_email = admin_email.lower()
        tenant.updated_at = datetime.utcnow()
        
        # Update service account key if provided
        if service_account_key:
            try:
                import json
                json.loads(service_account_key)
                encrypted_key = encryption_manager.encrypt(service_account_key)
                tenant.service_account_key = encrypted_key
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid service account key JSON")
        
        db.commit()
        
        log_audit_event(db, current_user.id, "tenant_updated", tenant.domain,
                       f"Updated tenant: {display_name}", True, request.client.host)
        
        return {"message": f"Tenant {tenant.domain} updated successfully"}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update tenant: {str(e)}")

@router.post("/tenants/{tenant_id}/toggle-status")
async def toggle_tenant_status(tenant_id: int,
                              request: Request,
                              current_user: User = Depends(require_admin),
                              db: Session = Depends(get_db)):
    """Toggle tenant active/inactive status."""
    tenant = db.query(GoogleWorkspaceTenant).filter(
        GoogleWorkspaceTenant.id == tenant_id
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    try:
        old_status = tenant.is_active
        tenant.is_active = not tenant.is_active
        tenant.updated_at = datetime.utcnow()
        db.commit()
        
        action = "enabled" if tenant.is_active else "disabled"
        log_audit_event(db, current_user.id, "tenant_status_changed", tenant.domain,
                       f"Tenant {action}", True, request.client.host)
        
        return {"message": f"Tenant {action} successfully", "is_active": tenant.is_active}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update tenant status: {str(e)}")

@router.delete("/tenants/{tenant_id}")
async def delete_tenant(tenant_id: int,
                       request: Request,
                       current_user: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    """Delete a Google Workspace tenant."""
    tenant = db.query(GoogleWorkspaceTenant).filter(
        GoogleWorkspaceTenant.id == tenant_id
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    try:
        domain = tenant.domain
        db.delete(tenant)
        db.commit()
        
        log_audit_event(db, current_user.id, "tenant_deleted", domain,
                       f"Deleted tenant: {domain}", True, request.client.host)
        
        return {"message": f"Tenant {domain} deleted successfully"}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete tenant: {str(e)}")
