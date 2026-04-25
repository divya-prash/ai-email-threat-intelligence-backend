"""
Main FastAPI Application - AI Email Threat Intelligence System
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import timedelta

import database
import models
import schemas
import auth
from spam_rules import detect_spam
from phishing_rules import detect_phishing
from risk_engine import compute_risk_score, classify_email
from ml_model import predict_malicious_score

# Create tables
database.Base.metadata.create_all(bind=database.engine)

# Initialize FastAPI app
app = FastAPI(
    title="AI Email Threat Intelligence API",
    description="A production-ready API for detecting email threats using ML and rule-based detection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*", "http://localhost:8000"],
    # allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== HEALTH CHECK ====================

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "AI Email Threat Intelligence API"}


# ==================== ADD USER ENDPOINT ====================

@app.post("/register", response_model=schemas.UserResponse, tags=["Auth"])
async def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    """
    Register a new user.
    
    - **username**: Unique username
    - **email**: Valid email address
    - **password**: Password (will be hashed)
    """
    # Check if user exists
    existing_user = db.query(models.User).filter(
        (models.User.username == user.username) | 
        (models.User.email == user.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username or email already exists"
        )
    
    # Create new user
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=auth.hash_password(user.password)
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

# ====================== LOGIN ENDPOINT ====================

@app.post("/login", response_model=schemas.Token, tags=["Auth"])
async def login(user: schemas.UserLogin, db: Session = Depends(database.get_db)):
    """
    Login with username and password to get JWT token.
    
    - **username**: Your username
    - **password**: Your password
    
    Returns access token to use for protected endpoints.
    """
    db_user = auth.authenticate_user(db, user.username, user.password)
    
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": db_user.username},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


# ==================== EMAIL ANALYSIS ENDPOINT ====================

@app.post("/analyze-email", response_model=schemas.EmailAnalysisResponse, tags=["Email Analysis"])
async def analyze_email(
    email: schemas.EmailAnalysisRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Analyze an email for spam and phishing threats.
    
    - **subject**: Email subject line
    - **body**: Email body/content
    - **sender**: Sender's email address
    
    Returns detailed threat assessment with risk score and classification.
    """
    def _save_analysis(spam_score: float, phishing_score: float, risk_score: float, classification: str):
        db_analysis = models.EmailAnalysis(
            user_id=current_user.id,
            subject=email.subject,
            sender=email.sender,
            spam_score=round(spam_score, 4),
            phishing_score=round(phishing_score, 4),
            risk_score=round(risk_score, 4),
            classification=classification,
        )
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)
        return db_analysis

    # 1) Rule engine first
    phishing_score = detect_phishing(email.subject, email.sender, email.body)
    if phishing_score > 0.9:
        return _save_analysis(0.0, phishing_score, 0.95, "HIGH RISK (rule-based)")

    # 2) Quick safe decision
    spam_score = detect_spam(email.subject, email.body)
    if phishing_score < 0.2 and spam_score < 0.2:
        return _save_analysis(spam_score, phishing_score, 0.1, "SAFE (rules)")

    # 3) ML when uncertain
    ml_score = predict_malicious_score(email.subject, email.body)
    risk_score = compute_risk_score((phishing_score + spam_score), ml_score)
    classification = classify_email(risk_score)

    return _save_analysis(spam_score, phishing_score, risk_score, classification)

# ==================== DASHBOARD ENDPOINT ====================

@app.get("/dashboard-stats", response_model=schemas.DashboardStats, tags=["Dashboard"])
async def get_dashboard_stats(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Get dashboard statistics for the current user.
    
    Returns:
    - **total_emails_analyzed**: Total number of emails analyzed
    - **high_risk_count**: Number of emails classified as "High Risk"
    - **suspicious_count**: Number of emails classified as "Suspicious"
    - **safe_count**: Number of emails classified as "Safe"
    """
    analyses = db.query(models.EmailAnalysis).filter(
        models.EmailAnalysis.user_id == current_user.id
    ).all()
    
    total = len(analyses)
    high_risk = sum(1 for a in analyses if a.classification == "High Risk")
    suspicious = sum(1 for a in analyses if a.classification == "Suspicious")
    safe = sum(1 for a in analyses if a.classification == "Safe")
    
    return schemas.DashboardStats(
        total_emails_analyzed=total,
        high_risk_count=high_risk,
        suspicious_count=suspicious,
        safe_count=safe
    )


# ==================== USER PROFILE ENDPOINT ====================

@app.get("/me", response_model=schemas.UserResponse, tags=["User"])
async def get_current_user_info(
    current_user: models.User = Depends(auth.get_current_user)
):
    """Get current authenticated user's information."""
    return current_user


# ==================== EMAIL HISTORY ENDPOINT ====================

@app.get("/email-history", tags=["Email Analysis"])
async def get_email_history(
    skip: int = 0,
    limit: int = 10,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Get email analysis history for the current user.
    
    - **skip**: Number of records to skip (for pagination)
    - **limit**: Maximum number of records to return
    """
    analyses = db.query(models.EmailAnalysis).filter(
        models.EmailAnalysis.user_id == current_user.id
    ).order_by(models.EmailAnalysis.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": db.query(models.EmailAnalysis).filter(
            models.EmailAnalysis.user_id == current_user.id
        ).count(),
        "analyses": analyses
    }

# ===================== MAIN ENTRY POINT ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
