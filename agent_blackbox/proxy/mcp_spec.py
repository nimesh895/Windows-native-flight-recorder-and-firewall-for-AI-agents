from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[int, str]] = None
    method: str
    params: Optional[Union[Dict[str, Any], List[Any]]] = None


class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[int, str]] = None
    result: Optional[Any] = None
    error: Optional[JsonRpcError] = None


def parse_json_rpc(line: str) -> Optional[Union[JsonRpcRequest, JsonRpcResponse]]:
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        if not isinstance(data, dict):
            return None
        if "method" in data:
            return JsonRpcRequest(**data)
        elif "result" in data or "error" in data:
            return JsonRpcResponse(**data)
        return None
    except Exception:
        return None


def serialize_json_rpc(msg: Union[JsonRpcRequest, JsonRpcResponse, dict]) -> str:
    if isinstance(msg, BaseModel):
        return msg.model_dump_json(exclude_none=True) + "\n"
    elif isinstance(msg, dict):
        return json.dumps(msg, ensure_ascii=False) + "\n"
    return str(msg) + "\n"
