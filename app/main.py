from fastapi import FastAPI,Depends
from routes.route import router
from models.model import employee
from auth.auth import authRouter
app=FastAPI()
app.include_router(router)
app.include_router(authRouter)
