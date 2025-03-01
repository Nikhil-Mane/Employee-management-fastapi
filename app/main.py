from fastapi import FastAPI
from routes.employee import router as employee_router
from auth.auth import authRouter

app = FastAPI()

app.include_router(employee_router)
app.include_router(authRouter)

@app.get("/")
def home():
    return {"message": "Welcome to FastAPI Authentication System"}
