from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
from database.db import get_db

load_dotenv()

EXPIRED_TIME_AFTER = int(os.getenv("EXPIRED_TIME_AFTER", 30))  # Default to 30 minutes
SECRET_ACCESS_KEY = os.getenv("SECRET_ACCESS_KEY", "your-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# OAuth2 Settings
authRouter = APIRouter(prefix="/auth")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# JWT Token Creation
def create_jwt_token(encode_data: dict):
    encode_data.update({"exp": datetime.utcnow() + timedelta(minutes=EXPIRED_TIME_AFTER)})
    return jwt.encode(encode_data, SECRET_ACCESS_KEY, algorithm=ALGORITHM)

# Login & Token Generation
@authRouter.post("/token")
def generate_token(
    grant_type: str = Form(...), 
    username: str = Form(None), 
    password: str = Form(None),
    scope: str = Form(""),
    db=Depends(get_db),
):
    if grant_type == "password":
        user = db.user.find_one({"username": username})
        if not user or not verify_password(password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        user_scopes = user.get("scopes", [])
        token = create_jwt_token({"user": username, "scopes": user_scopes})
        return {"access_token": token, "token_type": "bearer"}

    raise HTTPException(status_code=400, detail="Unsupported grant type")

# Secure Endpoint
@authRouter.get("/secure-data")
def secure_endpoint(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_ACCESS_KEY, algorithms=[ALGORITHM])
        user_scopes = payload.get("scopes", [])

        if "admin" not in user_scopes:
            raise HTTPException(status_code=403, detail="Forbidden: Requires 'admin' scope")

        return {"message": "Access granted", "scopes": user_scopes}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
