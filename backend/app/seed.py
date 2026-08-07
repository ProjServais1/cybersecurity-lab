"""Contenu d'exemple : 2 rooms (un parcours pentest, un parcours SOC).
Lancé au démarrage si la base est vide. Les flags vivent uniquement
côté serveur (champ `answer`)."""
from .database import SessionLocal
from . import models
from .auth import hash_password


def seed():
    db = SessionLocal()
    try:
        if db.query(models.Room).count() > 0:
            return

        # --- Compte admin de démonstration ---
        if not db.query(models.User).filter_by(username="admin").first():
            db.add(models.User(
                username="admin", email="admin@cyberlab.local",
                hashed_password=hash_password("admin1234"), is_admin=True))

        # ===================== ROOM 1 : PENTEST =====================
        pentest = models.Room(
            slug="injection-sql-101",
            title="Injection SQL 101",
            summary="Exploitez une appli web volontairement vulnérable et extrayez le flag.",
            category="pentest", difficulty="facile",
            docker_image="cyberlab/pentest-webapp:latest",  # construite dans labs/
            container_port=5000,
        )
        t1 = models.Task(order=1, title="Reconnaissance",
            content=("# Reconnaissance\n\nDémarrez la machine (bouton **Start**). "
                     "Une application web s'ouvre sur le port indiqué.\n\n"
                     "Explorez le formulaire de connexion. Inspectez son comportement "
                     "avec des entrées inattendues."))
        t1.questions = [
            models.Question(order=1,
                prompt="Quel paramètre HTTP est envoyé en POST par le formulaire de login ?",
                answer="username", hint="Regardez l'attribut name= du champ.", points=10),
        ]
        t2 = models.Task(order=2, title="Exploitation",
            content=("# Exploitation\n\nLe champ de connexion n'échappe pas les entrées. "
                     "Construisez une charge d'injection SQL pour contourner "
                     "l'authentification, puis récupérez le flag affiché après connexion.\n\n"
                     "Piste : `' OR '1'='1`"))
        t2.questions = [
            models.Question(order=1,
                prompt="Quel est le flag affiché après contournement de l'authentification ?",
                answer="CYBERLAB{sql_1nj3ct10n_b00m}",
                hint="Connectez-vous comme admin sans connaître le mot de passe.", points=40),
        ]
        pentest.tasks = [t1, t2]
        db.add(pentest)

        # ===================== ROOM 2 : SOC =====================
        soc = models.Room(
            slug="triage-alertes-soc",
            title="Triage d'alertes SOC : connexion suspecte",
            summary="Analysez des logs d'authentification et identifiez une attaque par force brute.",
            category="soc", difficulty="facile",
            docker_image=None, container_port=None,  # pas de machine : analyse de fichiers
        )
        s1 = models.Task(order=1, title="Le scénario",
            content=("# Le scénario\n\nVous êtes analyste SOC niveau 1. Un jeu de logs "
                     "`auth.log` vous est fourni (dossier *labs/soc-log-analysis/*). "
                     "Une alerte signale une possible attaque par force brute SSH.\n\n"
                     "Ouvrez le fichier et répondez aux questions ci-dessous."))
        s1.questions = [
            models.Question(order=1,
                prompt="Quelle adresse IP est à l'origine du plus grand nombre d'échecs de connexion ?",
                answer="203.0.113.42",
                hint="Comptez les occurrences de 'Failed password' par IP.", points=20),
            models.Question(order=2,
                prompt="Quel compte a finalement été compromis (connexion réussie depuis l'IP malveillante) ?",
                answer="deploy",
                hint="Cherchez 'Accepted password' depuis l'IP de l'attaquant.", points=30),
        ]
        s2 = models.Task(order=2, title="Réponse à incident",
            content=("# Réponse\n\nUne fois l'intrusion confirmée, la première mesure "
                     "de confinement consiste à bloquer la source et à révoquer la session."))
        s2.questions = [
            models.Question(order=1,
                prompt="Quelle technique MITRE ATT&CK correspond à une attaque par force brute (T-XXXX) ?",
                answer="T1110",
                hint="Catégorie 'Credential Access'.", points=20),
        ]
        soc.tasks = [s1, s2]
        db.add(soc)

        db.commit()
    finally:
        db.close()
