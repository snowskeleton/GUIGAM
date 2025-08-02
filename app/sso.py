"""
Microsoft SSO integration using MSAL (Microsoft Authentication Library)
"""

import msal
import requests
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models import SSOConfig, User, RoleMapping
from app.security import encryption_manager, generate_session_id, create_access_token
from datetime import datetime


class MicrosoftSSO:
    """Microsoft SSO handler."""
    
    def __init__(self, sso_config: SSOConfig):
        self.config = sso_config
        self.client_id = sso_config.client_id
        self.client_secret = encryption_manager.decrypt(sso_config.client_secret)
        self.tenant_id = sso_config.tenant_id
        self.redirect_uri = sso_config.redirect_uri
        
        # MSAL app instance
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}"
        )
    
    def get_auth_url(self, state: str) -> str:
        """Get Microsoft authorization URL."""
        scopes = ["User.Read", "GroupMember.Read.All"]
        
        auth_url = self.app.get_authorization_request_url(
            scopes=scopes,
            state=state,
            redirect_uri=self.redirect_uri
        )
        return auth_url
    
    def handle_callback(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """Handle OAuth callback and get user info."""
        try:
            # Exchange code for token
            result = self.app.acquire_token_by_authorization_code(
                code=code,
                scopes=["User.Read", "GroupMember.Read.All"],
                redirect_uri=self.redirect_uri
            )
            
            if "access_token" not in result:
                return None
            
            # Get user info from Microsoft Graph
            access_token = result["access_token"]
            user_info = self._get_user_info(access_token)
            if not user_info:
                return None
            
            # Get user's group memberships
            groups = self._get_user_groups(access_token)
            
            return {
                "user_info": user_info,
                "groups": groups,
                "access_token": access_token
            }
            
        except Exception as e:
            print(f"SSO callback error: {e}")
            return None
    
    def _get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from Microsoft Graph."""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            return None
            
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None
    
    def _get_user_groups(self, access_token: str) -> list:
        """Get user's group memberships."""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me/memberOf",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                groups = []
                for group in data.get("value", []):
                    if group.get("@odata.type") == "#microsoft.graph.group":
                        groups.append({
                            "id": group.get("id"),
                            "displayName": group.get("displayName"),
                            "mail": group.get("mail")
                        })
                return groups
            return []
            
        except Exception as e:
            print(f"Error getting user groups: {e}")
            return []


def get_sso_provider(provider: str, db: Session) -> Optional[MicrosoftSSO]:
    """Get SSO provider instance."""
    if provider.lower() != "microsoft":
        return None
    
    sso_config = db.query(SSOConfig).filter(
        SSOConfig.provider == "microsoft",
        SSOConfig.is_enabled == True
    ).first()
    
    if not sso_config:
        return None
    
    return MicrosoftSSO(sso_config)


def create_or_update_sso_user(user_info: Dict[str, Any], groups: list, db: Session) -> Optional[User]:
    """Create or update user from SSO information."""
    try:
        azure_id = user_info.get("id")
        email = user_info.get("mail") or user_info.get("userPrincipalName")
        display_name = user_info.get("displayName", "")
        
        if not azure_id or not email:
            return None
        
        # Determine user role based on group mappings
        user_role = determine_user_role(groups, db)
        
        # Check if user exists by Azure ID
        user = db.query(User).filter(User.azure_id == azure_id).first()
        
        if not user:
            # Check if user exists by email
            user = db.query(User).filter(User.email == email).first()
            
            if user:
                # Link existing user to Azure ID
                user.azure_id = azure_id
                user.role = user_role
            else:
                # Create new user
                username = email.split("@")[0]  # Use email prefix as username
                
                # Ensure username is unique
                counter = 1
                original_username = username
                while db.query(User).filter(User.username == username).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                user = User(
                    username=username,
                    email=email,
                    full_name=display_name,
                    azure_id=azure_id,
                    hashed_password=None,  # SSO users don't have passwords
                    is_active=True,
                    role=user_role
                )
                db.add(user)
        else:
            # Update existing user info
            user.email = email
            user.full_name = display_name
            user.role = user_role
            user.last_login = datetime.utcnow()
        
        db.commit()
        return user
        
    except Exception as e:
        db.rollback()
        print(f"Error creating/updating SSO user: {e}")
        return None


def determine_user_role(groups: list, db: Session) -> str:
    """Determine user role based on Azure group memberships."""
    try:
        group_ids = [group.get("id") for group in groups if group.get("id")]
        
        # Check role mappings - prioritize admin role
        role_mappings = db.query(RoleMapping).filter(
            RoleMapping.azure_group_id.in_(group_ids)
        ).all()
        
        # If user is in any admin group, they get admin role
        for mapping in role_mappings:
            if mapping.guigam_role == "admin":
                return "admin"
        
        # If user is in any mapped group but not admin, they get user role
        if role_mappings:
            return "user"
        
        # Default role if no group mappings found
        return "user"
        
    except Exception as e:
        print(f"Error determining user role: {e}")
        return "user"


def get_available_groups_for_admin(sso_config: SSOConfig) -> list:
    """Get all available groups from Microsoft Graph using app-only permissions."""
    try:
        # Create MSAL app for app-only authentication
        app = msal.ConfidentialClientApplication(
            client_id=sso_config.client_id,
            client_credential=encryption_manager.decrypt(sso_config.client_secret),
            authority=f"https://login.microsoftonline.com/{sso_config.tenant_id}"
        )
        
        # Get app-only token with Group.Read.All permission
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        
        if "access_token" not in result:
            print(f"Failed to get app token: {result.get('error_description', 'Unknown error')}")
            return []
        
        # Query Microsoft Graph for groups
        headers = {"Authorization": f"Bearer {result['access_token']}"}
        response = requests.get(
            "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mail,description&$top=999",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            groups = []
            for group in data.get("value", []):
                groups.append({
                    "id": group.get("id"),
                    "displayName": group.get("displayName"),
                    "mail": group.get("mail"),
                    "description": group.get("description", "")
                })
            return groups
        else:
            print(f"Graph API error: {response.status_code} - {response.text}")
            return []
        
    except Exception as e:
        print(f"Error getting available groups: {e}")
        return []


def get_available_groups(access_token: str) -> list:
    """Get all available groups from Microsoft Graph (for admin use) - legacy method."""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            groups = []
            for group in data.get("value", []):
                groups.append({
                    "id": group.get("id"),
                    "displayName": group.get("displayName"),
                    "mail": group.get("mail"),
                    "description": group.get("description")
                })
            return groups
        return []
        
    except Exception as e:
        print(f"Error getting available groups: {e}")
        return []


def validate_sso_config(client_id: str, client_secret: str, tenant_id: str, redirect_uri: str) -> bool:
    """Validate SSO configuration by testing connection."""
    try:
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}"
        )
        
        # Try to get an authorization URL - this validates the configuration
        app.get_authorization_request_url(
            scopes=["User.Read"],
            redirect_uri=redirect_uri
        )
        return True
        
    except Exception as e:
        print(f"SSO config validation error: {e}")
        return False
