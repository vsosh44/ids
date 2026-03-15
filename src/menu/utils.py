from typing import Any, get_origin, Optional
from pydantic import BaseModel

class FieldInfo(BaseModel):
    name: str
    value: object
    description: str
    annotation: Any
    annotation_name: str


def get_field_info(model: BaseModel, ind: int) -> FieldInfo:
    field = list(type(model).model_fields.items())[ind]
    name, info = field
    description = getattr(info, "description")
    value = getattr(model, name)

    raw_annotation = getattr(info, "annotation")
    origin = get_origin(raw_annotation)
    normalized_annotation = origin if origin is not None else raw_annotation

    if not isinstance(normalized_annotation, type):
        normalized_annotation = str

    annotation_name = getattr(raw_annotation, "__name__", str(raw_annotation))

    return FieldInfo(
        name=name,
        value=value,
        description=description if description else "",
        annotation=normalized_annotation,
        annotation_name=annotation_name
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
