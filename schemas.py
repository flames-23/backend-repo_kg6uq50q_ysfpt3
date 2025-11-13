"""
Database Schemas for Medi-Friend

Each Pydantic model corresponds to a MongoDB collection. The collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Hashed password (server-side only)")
    notifications_enabled: bool = Field(True, description="Whether user allows notifications")

class Session(BaseModel):
    user_id: str = Field(..., description="User ID this session belongs to")
    token: str = Field(..., description="Opaque session token")
    expires_at: datetime = Field(..., description="UTC expiration time")

class Medication(BaseModel):
    user_id: str = Field(..., description="Owner user ID")
    name: str = Field(..., description="Medicine name")
    dosage: str = Field(..., description="Dosage e.g., 1 tablet, 2ml")
    time_12h: str = Field(..., description="Time in 12-hour format, e.g., 08:30 PM")
    frequency: Literal['daily','alternate','weekly'] = Field('daily', description="Reminder frequency")
    last_taken_at: Optional[datetime] = Field(None, description="UTC timestamp of last time taken")
    snooze_until_utc: Optional[datetime] = Field(None, description="UTC timestamp until which reminder is snoozed")
    notes: Optional[str] = Field(None, description="Additional notes")
