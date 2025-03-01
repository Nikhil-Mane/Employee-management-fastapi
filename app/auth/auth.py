from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional, List

# Constants
EXPIRED_TIME_AFTER = 30  # Token expiry time in minutes
SECRET_ACCESS_KEY = "your-secret-key"
ALGORITHM = "HS256"

# OAuth2 Settings
authRouter = APIRouter(prefix="/auth")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/token",
    scheme_name="Bearer",
    scopes={"admin": "Administrator access", "user": "Regular user access"},
    description="Login with different roles and permissions",
)

# Simulated Database for Users and Clients
FAKE_USERS_DB = {
    "admin": {"username": "admin", "password": "password", "scopes": ["admin", "user"]},
    "user": {"username": "user", "password": "userpass", "scopes": ["user"]},
}

FAKE_CLIENTS_DB = {
    "client_123": {"client_secret": "secret_456", "scopes": ["user"]},  # This client cannot access "admin" scope
}


# Helper Function to Create JWT Token
def create_jwt_token(encode_data: dict):
    encode_data.update({"exp": datetime.utcnow() + timedelta(minutes=EXPIRED_TIME_AFTER)})
    return jwt.encode(encode_data, SECRET_ACCESS_KEY, algorithm=ALGORITHM)


# Token Endpoint Supporting Permission Checks
@authRouter.post("/token")
def generate_token(
    grant_type: str = Form(...),  # Required grant type
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    scope: Optional[str] = Form(""),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
):
    """Handles authentication and ensures requested scopes are allowed."""

    # Handle Password Grant
    if grant_type == "password":
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password are required for password grant")
        
        user = FAKE_USERS_DB.get(username)
        if not user or user["password"] != password:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        user_scopes = user["scopes"]
        requested_scopes = scope.split() if scope else user_scopes

        # Validate requested scopes
        if not set(requested_scopes).issubset(set(user_scopes)):
            raise HTTPException(status_code=403, detail=f"Insufficient permissions. Allowed scopes: {user_scopes}")

        token = create_jwt_token({"user": username, "scopes": requested_scopes})
        return {"access_token": token, "token_type": "bearer"}

    # Handle Client Credentials Grant
    elif grant_type == "client_credentials":
        if not client_id or not client_secret:
            raise HTTPException(status_code=400, detail="Client ID and secret are required for client_credentials grant")
        
        client = FAKE_CLIENTS_DB.get(client_id)
        if not client or client["client_secret"] != client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        client_scopes = client["scopes"]
        requested_scopes = scope.split() if scope else client_scopes

        # Validate requested scopes
        if not set(requested_scopes).issubset(set(client_scopes)):
            raise HTTPException(status_code=403, detail=f"Insufficient permissions. Allowed scopes: {client_scopes}")

        token = create_jwt_token({"client": client_id, "scopes": requested_scopes})
        return {"access_token": token, "token_type": "bearer"}

    # Unsupported Grant Type
    raise HTTPException(status_code=400, detail="Unsupported grant type")


# Secure Endpoint with Scope-Based Access Control
@authRouter.get("/secure-data")
def secure_endpoint(token: str = Depends(oauth2_scheme)):
    """Example protected route that requires authentication and scope checking"""
    try:
        payload = jwt.decode(token, SECRET_ACCESS_KEY, algorithms=[ALGORITHM])
        user_scopes = payload.get("scopes", [])

        if "admin" not in user_scopes:
            raise HTTPException(status_code=403, detail="Forbidden: Requires 'admin' scope")

        return {"message": "Access granted", "scopes": user_scopes}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
