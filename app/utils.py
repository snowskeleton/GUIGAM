from fastapi import Request, Depends
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from app.database import get_db
from app.models import User, UserSession, AuditLog

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
    
    from app.security import verify_token
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