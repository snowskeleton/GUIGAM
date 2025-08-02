from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)  # Nullable for SSO-only users
    full_name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # SSO fields
    azure_id = Column(String(255), unique=True, nullable=True, index=True)
    
    # Role field
    role = Column(String(20), default="user")  # "user" or "admin"
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    

class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")


class SSOConfig(Base):
    __tablename__ = "sso_config"
    
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), nullable=False)  # 'microsoft', 'google', etc.
    client_id = Column(String(255), nullable=False)
    client_secret = Column(Text, nullable=False)  # Encrypted
    tenant_id = Column(String(255), nullable=True)  # For Microsoft
    redirect_uri = Column(String(255), nullable=False)
    is_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class GoogleWorkspaceTenant(Base):
    __tablename__ = "workspace_tenants"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    service_account_key = Column(Text, nullable=False)  # Encrypted JSON
    admin_email = Column(String(100), nullable=False)  # For impersonation
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RoleMapping(Base):
    __tablename__ = "role_mappings"
    
    id = Column(Integer, primary_key=True, index=True)
    azure_group_id = Column(String(255), nullable=False, index=True)
    azure_group_name = Column(String(255), nullable=False)
    guigam_role = Column(String(20), nullable=False)  # "user" or "admin"
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # 'login', 'gam_command', 'config_change'
    resource = Column(String(255), nullable=True)  # Tenant domain, user email, etc.
    details = Column(Text, nullable=True)  # JSON details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User")