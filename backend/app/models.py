"""Modèle de données.

Vocabulaire (calqué sur les plateformes de cyber-entraînement) :
- Room  : un module/labo (ex. "Injection SQL", "Triage d'alertes SOC")
- Task  : une étape d'une room, avec des questions
- Question : une question dont la réponse est un flag à valider
- Progress : ce qu'un utilisateur a déjà résolu (points, flags trouvés)
"""
from datetime import datetime
from sqlalchemy import (Column, Integer, String, Text, Boolean, DateTime,
                        ForeignKey, UniqueConstraint)
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    points = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    completions = relationship("Completion", back_populates="user",
                               cascade="all, delete-orphan")


class Room(Base):
    __tablename__ = "rooms"
    id = Column(Integer, primary_key=True)
    slug = Column(String(80), unique=True, nullable=False, index=True)
    title = Column(String(160), nullable=False)
    summary = Column(String(300))
    # category : "pentest" ou "soc" — sert à filtrer les deux parcours
    category = Column(String(40), nullable=False)
    difficulty = Column(String(20), default="facile")   # facile|moyen|difficile
    # Image Docker à lancer pour la machine vulnérable (optionnel pour le SOC)
    docker_image = Column(String(200), nullable=True)
    # Port interne exposé par le conteneur de labo
    container_port = Column(Integer, nullable=True)
    published = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    tasks = relationship("Task", back_populates="room",
                         cascade="all, delete-orphan", order_by="Task.order")


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True)
    room_id = Column(Integer, ForeignKey("rooms.id"), nullable=False)
    order = Column(Integer, default=0)
    title = Column(String(200), nullable=False)
    content = Column(Text)  # consignes / cours (Markdown)

    room = relationship("Room", back_populates="tasks")
    questions = relationship("Question", back_populates="task",
                             cascade="all, delete-orphan", order_by="Question.order")


class Question(Base):
    __tablename__ = "questions"
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)
    order = Column(Integer, default=0)
    prompt = Column(String(400), nullable=False)
    # Le flag attendu n'est JAMAIS envoyé au client : validation côté serveur.
    answer = Column(String(300), nullable=False)
    hint = Column(String(400))
    points = Column(Integer, default=10)

    task = relationship("Task", back_populates="questions")


class Completion(Base):
    __tablename__ = "completions"
    __table_args__ = (UniqueConstraint("user_id", "question_id"),)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    question_id = Column(Integer, ForeignKey("questions.id"), nullable=False)
    solved_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="completions")
