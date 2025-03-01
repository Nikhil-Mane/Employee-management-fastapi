import json
from fastapi import APIRouter, Depends, HTTPException
from models.model import Employee
from auth.auth import oauth2_scheme, hash_password
from database.db import get_db

router = APIRouter(prefix="/employee")


# 🔹 Unprotected Route (Signup)
@router.post("/signup", tags=["Auth"])  # No authentication required
def signup(user: Employee, db=Depends(get_db)):
    existing_user = db.user.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user.password)
    db.user.insert_one(
        {"username": user.username, "password": hashed_password, "scopes": user.scopes}
    )

    return {"message": "User registered successfully"}


@router.post("/store", dependencies=[Depends(oauth2_scheme)], tags=["Employee"])
def store_employee_Data(employee: Employee):
    with open("data.json", "a+") as f:
        f.write(employee.json() + "\n")
    return {"message": "Employee stored", "data": employee}


@router.get("/user", dependencies=[Depends(oauth2_scheme)], tags=["Employee"])
def fetch_user_Data(db=Depends(get_db)):
    users = list(db.user.find({}, {"_id": 0}))
    return {"message": "Fetched", "data": users}
