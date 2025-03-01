from pydantic import BaseModel
from typing import List, Optional

class Employee(BaseModel):
    username: str
    password: str
    scopes: Optional[List[str]] = ["user"]
