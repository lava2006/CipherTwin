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
        log_event(db, action="login_failed", actor=payload.username,
                  severity="warning",
                  ip_address=request.client.host if request.client else None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User disabled")

    token = create_access_token(user.username, user.role)
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    log_event(db, action="login", actor=user.username, severity="info",
              ip_address=request.client.host if request.client else None)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut.model_validate(user)


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    log_event(db, action="logout", actor=user.username, severity="info",
              ip_address=request.client.host if request.client else None)
    return {"detail": "Logged out"}
