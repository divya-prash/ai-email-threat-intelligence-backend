from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class User(Base):
    """User model for authentication."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    email_analyses = relationship("EmailAnalysis", back_populates="user")


class EmailAnalysis(Base):
    """Email analysis results model."""
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    subject = Column(String)
    sender = Column(String)
    spam_score = Column(Float)
    phishing_score = Column(Float)
    risk_score = Column(Float)
    classification = Column(String)  # Safe, Suspicious, High Risk
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    user = relationship("User", back_populates="email_analyses")
