"""Authentification : mots de passe hachés (bcrypt) + jetons JWT."""
import os
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .database import get_db
from . import models

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE-ME-en-production-svp")
ALGORITHM = "HS256"
TOKEN_TTL_MIN = int(os.getenv("TOKEN_TTL_MIN", "720"))

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(p: str) -> str:
    return pwd.hash(p)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd.verify(plain, hashed)


def create_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_TTL_MIN)
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> models.User:
    cred_err = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Identifiants invalides",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise cred_err
    user = db.query(models.User).get(uid)
    if not user:
        raise cred_err
    return user


def admin_only(user: models.User = Depends(current_user)) -> models.User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs")
    return user
