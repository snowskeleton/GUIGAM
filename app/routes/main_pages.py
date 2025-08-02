from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_
from typing import Optional

from app.database import get_db
from app.models import User, AuditLog, SSOConfig
from app.dependencies import require_auth_page, require_auth

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def main_page(request: Request, current_user: User = Depends(require_auth_page)):
    """Main dashboard - requires authentication."""
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user
    })

@router.get("/login", response_class=HTMLResponse)
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

@router.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request, current_user: User = Depends(require_auth_page)):
    """Audit logs page."""
    return templates.TemplateResponse("audit_logs.html", {"request": request, "user": current_user})

@router.get("/audit-logs/data")
async def get_audit_logs(request: Request,
                        current_user: User = Depends(require_auth),
                        page: int = Query(1, ge=1),
                        limit: int = Query(50, ge=1, le=100),
                        action: Optional[str] = Query(None),
                        success: Optional[bool] = Query(None),
                        db: Session = Depends(get_db)):
    """Get audit logs data."""
    
    # Base query
    query = db.query(AuditLog).join(User, AuditLog.user_id == User.id, isouter=True)
    
    # Apply filters
    filters = []
    if action:
        filters.append(AuditLog.action.ilike(f"%{action}%"))
    if success is not None:
        filters.append(AuditLog.success == success)
    
    if filters:
        query = query.filter(and_(*filters))
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    offset = (page - 1) * limit
    logs = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit).all()
    
    # Format response
    log_data = []
    for log in logs:
        user_name = "System"
        if log.user_id and log.user:
            user_name = log.user.full_name
        elif log.user_id:
            user_name = f"User {log.user_id}"
        
        log_data.append({
            "id": log.id,
            "user_name": user_name,
            "action": log.action,
            "resource": log.resource,
            "details": log.details,
            "success": log.success,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat()
        })
    
    total_pages = (total + limit - 1) // limit  # Ceiling division
    
    return {
        "logs": log_data,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages
    }