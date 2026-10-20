"""Authentication endpoints."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.deps import get_current_user
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse, UserOut
from app.services.audit import log_event


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User disabled")

    token = create_access_token(user.username, user.role)
    user.last_login = datetime.now(timezone.utc)

    # Track active session in Digital Twin
    from app.models.session import ActiveSession
    client_ip = request.client.host if request.client else "127.0.0.1"
    existing_sess = db.query(ActiveSession).filter(
        ActiveSession.user_id == user.username,
        ActiveSession.status == "active",
    ).first()
    if existing_sess:
        existing_sess.last_activity = datetime.now(timezone.utc)
        existing_sess.ip_address = client_ip
    else:
        db.add(ActiveSession(
            user_id=user.username,
            device_id="admin-workstation" if user.role == "admin" else "analyst-terminal",
            ip_address=client_ip,
            location="SOC Command Center",
            risk_score=15,
            status="active",
        ))
    db.commit()

    log_event(db, action="login", actor=user.username, severity="info",
              ip_address=client_ip)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut.model_validate(user)


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    from app.models.session import ActiveSession
    active_sess = db.query(ActiveSession).filter(
        ActiveSession.user_id == user.username,
        ActiveSession.status == "active",
    ).first()
    if active_sess:
        active_sess.status = "terminated"
        db.commit()

    log_event(db, action="logout", actor=user.username, severity="info",
              ip_address=request.client.host if request.client else None)
    return {"detail": "Logged out"}
