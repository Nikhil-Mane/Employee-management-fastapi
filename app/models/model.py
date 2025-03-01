from pydantic import BaseModel,Field
from typing import Optional,Annotated

class employee(BaseModel):
    id:int
    name:str=Field(...,min_length=2,max_length=10)
    surname:str|None
    mobile:Optional[int|None]=None