""" RwSchema py """
from datetime import datetime
from base import to_camel, format_datetime
from pydantic import BaseModel as RwModel
# ========== Pydantic Base Schema ==========
class RWSchema(RwModel):
    class Config:
        orm_mode = True
        populate_by_name = True
        alias_generator = to_camel
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: format_datetime
        }

