"""Point d'entrée de l'API CyberLab.

Endpoints principaux :
  POST /api/auth/register          créer un compte
  POST /api/auth/login             obtenir un jeton JWT
  GET  /api/rooms?category=pentest lister les rooms (filtre pentest/soc)
  GET  /api/rooms/{slug}           détail d'une room (sans les flags)
  POST /api/questions/{id}/submit  soumettre une réponse / flag
  POST /api/rooms/{slug}/lab/start démarrer la machine vulnérable
  POST /api/rooms/{slug}/lab/stop  l'arrêter
  GET  /api/me                     profil + progression
  GET  /api/leaderboard            classement
"""
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func

from .database import Base, engine, get_db
from . import models, auth, lab_engine
from .seed import seed
from pydantic import BaseModel, EmailStr

Base.metadata.create_all(bind=engine)
seed()

app = FastAPI(title="CyberLab API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


# --------- Schémas d'E/S ---------
class RegisterIn(BaseModel):
    username: str
    email: EmailStr
    password: str

class SubmitIn(BaseModel):
    answer: str


# --------- Auth ---------
@app.post("/api/auth/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(models.User).filter_by(username=data.username).first():
        raise HTTPException(400, "Nom d'utilisateur déjà pris")
    if db.query(models.User).filter_by(email=data.email).first():
        raise HTTPException(400, "Email déjà utilisé")
    u = models.User(username=data.username, email=data.email,
                    hashed_password=auth.hash_password(data.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"token": auth.create_token(u.id), "username": u.username}


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.query(models.User).filter_by(username=form.username).first()
    if not u or not auth.verify_password(form.password, u.hashed_password):
        raise HTTPException(401, "Identifiants incorrects")
    return {"access_token": auth.create_token(u.id), "token_type": "bearer",
            "username": u.username, "is_admin": u.is_admin}


# --------- Rooms ---------
@app.get("/api/rooms")
def list_rooms(category: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Room).filter_by(published=True)
    if category:
        q = q.filter_by(category=category)
    return [{"slug": r.slug, "title": r.title, "summary": r.summary,
             "category": r.category, "difficulty": r.difficulty,
             "has_machine": bool(r.docker_image)} for r in q.all()]


@app.get("/api/rooms/{slug}")
def get_room(slug: str, db: Session = Depends(get_db),
             user: models.User = Depends(auth.current_user)):
    r = db.query(models.Room).filter_by(slug=slug).first()
    if not r:
        raise HTTPException(404, "Room introuvable")
    solved = {c.question_id for c in user.completions}
    return {
        "slug": r.slug, "title": r.title, "summary": r.summary,
        "category": r.category, "difficulty": r.difficulty,
        "has_machine": bool(r.docker_image),
        "tasks": [{
            "id": t.id, "title": t.title, "content": t.content,
            "questions": [{  # le flag (answer) n'est jamais exposé
                "id": qn.id, "prompt": qn.prompt, "hint": qn.hint,
                "points": qn.points, "solved": qn.id in solved
            } for qn in t.questions]
        } for t in r.tasks]
    }


# --------- Soumission de flag ---------
@app.post("/api/questions/{qid}/submit")
def submit(qid: int, data: SubmitIn, db: Session = Depends(get_db),
           user: models.User = Depends(auth.current_user)):
    qn = db.query(models.Question).get(qid)
    if not qn:
        raise HTTPException(404, "Question introuvable")
    correct = data.answer.strip().lower() == qn.answer.strip().lower()
    if not correct:
        return {"correct": False}
    already = db.query(models.Completion).filter_by(
        user_id=user.id, question_id=qid).first()
    if not already:
        db.add(models.Completion(user_id=user.id, question_id=qid))
        user.points += qn.points
        db.commit()
    return {"correct": True, "points": qn.points, "total_points": user.points}


# --------- Machine de labo ---------
@app.post("/api/rooms/{slug}/lab/start")
def lab_start(slug: str, db: Session = Depends(get_db),
              user: models.User = Depends(auth.current_user)):
    r = db.query(models.Room).filter_by(slug=slug).first()
    if not r or not r.docker_image:
        raise HTTPException(400, "Cette room n'a pas de machine à lancer")
    try:
        return lab_engine.start_lab(user.id, r.docker_image, r.container_port)
    except Exception as e:
        raise HTTPException(503, f"Moteur Docker indisponible : {e}")


@app.post("/api/rooms/{slug}/lab/stop")
def lab_stop(slug: str, user: models.User = Depends(auth.current_user)):
    return lab_engine.stop_lab(user.id)


@app.get("/api/lab/status")
def lab_st(user: models.User = Depends(auth.current_user)):
    return lab_engine.lab_status(user.id)


# --------- Profil & classement ---------
@app.get("/api/me")
def me(db: Session = Depends(get_db), user: models.User = Depends(auth.current_user)):
    return {"username": user.username, "email": user.email,
            "points": user.points, "is_admin": user.is_admin,
            "solved": len(user.completions)}


@app.get("/api/leaderboard")
def leaderboard(db: Session = Depends(get_db)):
    rows = (db.query(models.User.username, models.User.points)
            .order_by(models.User.points.desc()).limit(50).all())
    return [{"username": u, "points": p} for u, p in rows]


@app.get("/api/health")
def health():
    return {"status": "ok"}
