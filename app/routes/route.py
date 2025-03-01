from fastapi import APIRouter,Depends
from models.model import employee
import json
from auth.auth import oauth2_scheme
from database.db import get_db

router=APIRouter(prefix="/employee",tags=["Employee"],dependencies=[Depends(oauth2_scheme)])

@router.get("/")
def fetch_employee_Data():
    return {"message":"Fetched","data":{}}

@router.post("/store")
def store_employee_Data(employee:employee):
    print(employee)
    with open("data.json","a+") as f:
        f.write(employee.json())
    return {"message":"employee stored","data":employee}

@router.post("/user")
def store_user_Data(user:employee,db=Depends(get_db)):
    db.user.insert_one(user.dict())
    return {"message":"user stored","data":user}

@router.get("/user")
def fetch_user_Data(db=Depends(get_db)):
    users=list(db.user.find({},{"_id":0}))
    print(users)
    
    return {"message":"Fetched","data":users}
