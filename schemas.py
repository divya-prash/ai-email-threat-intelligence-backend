from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


class EmailAnalysisRequest(BaseModel):
    subject: str
    body: str
    sender: str


class EmailAnalysisResponse(BaseModel):
    id: int
    subject: str
    sender: str
    spam_score: float
    phishing_score: float
    risk_score: float
    classification: str
    created_at: datetime

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_emails_analyzed: int
    high_risk_count: int
    suspicious_count: int
    safe_count: int
