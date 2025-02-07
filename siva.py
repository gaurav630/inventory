import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import math 
import hashlib
import hashlib
import jwt
import datetime
import sqlite3
import streamlit as st
from contextlib import contextmanager

# Database functions
@contextmanager
def get_db(db_path="auth.db"):
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    with get_db() as conn:
        cursor = conn.cursor()
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires TIMESTAMP NOT NULL,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')
        conn.commit()

def init_default_admin():
    with get_db() as conn:
        cursor = conn.cursor()
        # Check if admin exists
        cursor.execute("SELECT 1 FROM users WHERE username = ?", ("User Harsh",))
        if not cursor.fetchone():
            # Create default admin
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("User Harsh", 
                 hashlib.sha256('9838'.encode()).hexdigest(),
                 "Admin")
            )
            conn.commit()

# Authentication functions
def get_role_permissions():
    return {
        'Admin': ['overview', 'inventory_status', 'shipment_planning', 'loss_analysis', 
                 'profit_analysis', 'max_drr', 'drr_timeline', 'labels', 'manage_users'],
        'admin': ['overview', 'inventory_status', 'shipment_planning', 'loss_analysis', 
                 'profit_analysis', 'max_drr', 'drr_timeline', 'labels'],
        'inventory': ['overview', 'inventory_status', 'shipment_planning', 'max_drr', 'drr_timeline'],
        'Labels': ['overview', 'labels'],
        'viewer': ['overview']
    }

def create_token(username, secret_key="your-secret-key", expiry_hours=24):
    expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)
    token = jwt.encode(
        {'username': username, 'exp': expiry},
        secret_key,
        algorithm='HS256'
    )
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (token, username, expires) VALUES (?, ?, ?)",
            (token, username, expiry)
        )
        conn.commit()
    
    return token

def verify_token(token, secret_key="your-secret-key"):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username FROM sessions WHERE token = ? AND expires > ?",
                (token, datetime.datetime.utcnow())
            )
            result = cursor.fetchone()
            if result:
                return result[0]
    except:
        pass
    return None

def login(username, password):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT role FROM users WHERE username = ? AND password = ?",
            (username, hashlib.sha256(password.encode()).hexdigest())
        )
        result = cursor.fetchone()
        if result:
            token = create_token(username)
            return True, token, result[0]
    return False, None, None

def add_user(username, password, role):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return False, "Username already exists"
        
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashlib.sha256(password.encode()).hexdigest(), role)
        )
        conn.commit()
        return True, "User added successfully"

def remove_user(username):
    if username == 'User Harsh':
        return False, "Cannot remove admin user"
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        if cursor.rowcount > 0:
            conn.commit()
            return True, "User removed successfully"
        return False, "User not found"

def update_user_role(username, new_role):
    if username == 'User Harsh':
        return False, "Cannot modify admin role"
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ? WHERE username = ?",
            (new_role, username)
        )
        if cursor.rowcount > 0:
            conn.commit()
            return True, "Role updated successfully"
        return False, "User not found"

def get_user_role(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None

def get_all_users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, role FROM users")
        return cursor.fetchall()

# Streamlit interface functions
def init_auth():
    if 'db_initialized' not in st.session_state:
        init_database()
        init_default_admin()
        st.session_state.db_initialized = True

def check_password():
    init_auth()
    
    # Check for existing token in cookies
    if 'auth_token' in st.session_state:
        username = verify_token(st.session_state.auth_token)
        if username:
            st.session_state.current_user = username
            st.session_state.current_role = get_user_role(username)
            return True

    st.title("Login")
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("Username")
    with col2:
        password = st.text_input("Password", type="password")

    if st.button("Login"):
        success, token, role = login(username, password)
        if success:
            st.session_state.auth_token = token
            st.session_state.current_user = username
            st.session_state.current_role = role
            st.rerun()
        else:
            st.error("Invalid credentials")
    return False

def has_permission(permission):
    return permission in get_role_permissions()[st.session_state.current_role]

def user_management():
    if st.session_state.current_user != 'User Harsh':
        st.warning("Only admin can manage users")
        return

    st.subheader("User Management")
    
    tab1, tab2, tab3 = st.tabs(["Add User", "Remove User", "Update Role"])
    
    with tab1:
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        new_role = st.selectbox("Select Role", options=list(get_role_permissions().keys()))
        if st.button("Add User"):
            success, message = add_user(new_username, new_password, new_role)
            if success:
                st.success(message)
            else:
                st.error(message)

    with tab2:
        users = get_all_users()
        username_to_remove = st.selectbox(
            "Select User to Remove", 
            options=[u[0] for u in users if u[0] != 'User Harsh']
        )
        if st.button("Remove User"):
            success, message = remove_user(username_to_remove)
            if success:
                st.success(message)
            else:
                st.error(message)

    with tab3:
        users = get_all_users()
        username_to_update = st.selectbox(
            "Select User to Update", 
            options=[u[0] for u in users if u[0] != 'User Harsh']
        )
        new_role = st.selectbox(
            "Select New Role", 
            options=list(get_role_permissions().keys()),
            key="update_role"
        )
        if st.button("Update Role"):
            success, message = update_user_role(username_to_update, new_role)
            if success:
                st.success(message)
            else:
                st.error(message)

    st.write("Current Users:")
    users = get_all_users()
    user_list = pd.DataFrame(
        [(user, role, ', '.join(get_role_permissions()[role])) 
         for user, role in users],
        columns=["Username", "Role", "Permissions"]
    )
    st.dataframe(user_list)
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import tempfile
import os

def clear_session():
    # Clear all session state variables
    for key in list(st.session_state.keys()):
        del st.session_state[key]

def main():
    if not check_password():
        return

    st.sidebar.title(f"Welcome, {st.session_state.current_user}")
    st.sidebar.write(f"Role: {st.session_state.current_role}")
    
    if st.sidebar.button("Logout"):
        # Remove the auth token from session and clear session state
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE token = ?", 
                         (st.session_state.auth_token,))
            conn.commit()
        clear_session()
        st.rerun()

    if st.session_state.current_user == 'User Harsh':
        if st.sidebar.button("Manage Users"):
            st.session_state.show_user_management = True
        
    if st.session_state.get('show_user_management', False):
        user_management()
        if st.button("Back to Dashboard"):
            st.session_state.show_user_management = False
            st.rerun()
        return
    #

if _name_ == "__main__":
    main()
