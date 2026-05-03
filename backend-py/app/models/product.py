"""Pydantic models for product inventory and CPE resolution."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class CpeResolution(BaseModel):
    input_string: str
    resolved_cpe: str
    confidence: Literal["certain", "uncertain", "manual"]
    match_score: float | None = None
    resolved_by: Literal["auto", "manual"] = "auto"
    from_cache: bool = False
