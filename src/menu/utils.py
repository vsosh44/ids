from pydantic import BaseModel
from typing import Optional, Any

class FieldInfo(BaseModel):
    name: str
    value: object
    description: str
    annotation: type


def get_field_info(model: BaseModel, ind: int) -> FieldInfo:
    field = list(type(model).model_fields.items())[ind]
    name, info = field
    description = getattr(info, "description")
    value = getattr(model, name)
    annotation = getattr(info, "annotation")
    return FieldInfo(
        name=name,
        value=value,
        description=description if description else "",
        annotation=annotation
    )


def ret_str_type(s: str, t: type) -> Optional[Any]:
    try:
        if t is bool:
            if s.lower() == "true": return True
            elif s.lower() == "false": return False
            else: return None
        
        return t(s)
    except (ValueError, TypeError):
        return None
