#!/usr/bin/env python3
"""
Database setup script for GAM Web Interface.
Creates initial database and admin user.
"""

import sys
import getpass
from sqlalchemy.orm import Session
from app.database import engine, SessionLocal, create_tables
from app.models import User
from app.security import get_password_hash, validate_password_strength

def create_admin_user():
    """Create the initial admin user."""
    print("Setting up GAM Web Interface Database")
    print("=" * 40)
    
    # Create tables
    print("Creating database tables...")
    create_tables()
    print("✓ Database tables created")
    
    # Create admin user
    print("\nCreating admin user...")
    
    while True:
        username = input("Admin username: ").strip()
        if username:
            break
        print("Username cannot be empty")
    
    while True:
        email = input("Admin email: ").strip()
        if email and "@" in email:
            break
        print("Please enter a valid email address")
    
    while True:
        full_name = input("Admin full name: ").strip()
        if full_name:
            break
        print("Full name cannot be empty")
    
    while True:
        password = getpass.getpass("Admin password: ")
        if not password:
            print("Password cannot be empty")
            continue
            
        if not validate_password_strength(password):
            print("Password must be at least 8 characters and contain:")
            print("- One uppercase letter")
            print("- One lowercase letter") 
            print("- One number")
            print("- One special character (!@#$%^&*(),.?\":{}|<>)")
            continue
            
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match")
            continue
            
        break
    
    # Check if user already exists
    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"User '{username}' already exists!")
            return
        
        existing_email = db.query(User).filter(User.email == email).first()
        if existing_email:
            print(f"Email '{email}' already exists!")
            return
        
        # Create admin user
        admin_user = User(
            username=username,
            email=email,
            full_name=full_name,
            hashed_password=get_password_hash(password),
            is_active=True,
            is_first_login=False  # Skip first login for setup
        )
        
        db.add(admin_user)
        db.commit()
        
        print(f"✓ Admin user '{username}' created successfully!")
        print(f"\nYou can now start the application with:")
        print(f"  python -m uvicorn app.main:app --reload")
        print(f"\nThen visit: http://localhost:8000")
        
    except Exception as e:
        db.rollback()
        print(f"Error creating user: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    try:
        create_admin_user()
    except KeyboardInterrupt:
        print("\nSetup cancelled.")
        sys.exit(1)