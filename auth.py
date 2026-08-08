"""
auth.py
-------
Simple session-based authentication restricting the Sentry dashboard to
Security Department members only.

This is intentionally lightweight for a prototype/college-project stage:
a small in-memory user store with hashed passwords and Flask's built-in
signed session cookies. No database is needed. In a production system
this would be swapped for a real identity provider (LDAP/SSO/etc.).
"""

from functools import wraps
from flask import session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------------------
# Security Department member accounts (demo credentials for the review).
# In a real deployment these would live in a proper user database.
# --------------------------------------------------------------------
_USERS = {
    "admin": {
        "password_hash": generate_password_hash("Sentry@123"),
        "full_name": "Security Admin",
        "role": "Security Department",
    },
    "sk.parveen": {
        "password_hash": generate_password_hash("Sentry@123"),
        "full_name": "SK Parveen",
        "role": "Security Department",
    },
    "r.sivateja": {
        "password_hash": generate_password_hash("Sentry@123"),
        "full_name": "R Siva Teja",
        "role": "Security Department",
    },
}


def verify_login(username, password):
    """Returns the user's profile dict if credentials are valid, else None."""
    user = _USERS.get(username)
    if user and check_password_hash(user["password_hash"], password):
        return {"username": username, "full_name": user["full_name"], "role": user["role"]}
    return None


def current_user():
    """Returns the logged-in user's profile from the session, or None."""
    if "username" in session:
        return {
            "username": session["username"],
            "full_name": session.get("full_name"),
            "role": session.get("role"),
        }
    return None


def login_required(view_func):
    """
    Decorator protecting a route so only authenticated Security Department
    members can access it. Redirects anonymous visitors to the login page,
    remembering where they were headed so we can send them back after
    they sign in.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped
