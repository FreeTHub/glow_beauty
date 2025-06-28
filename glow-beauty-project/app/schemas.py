""" Raw Model """
from pydantic import BaseModel

class RWModel(BaseModel):
    class Config:
        orm_mode = True
        # Add any global config for your Pydantic models here
