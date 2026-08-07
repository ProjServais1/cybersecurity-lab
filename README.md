# CyberLab — plateforme d'entraînement Pentest & SOC (auto-hébergeable, gratuite, portable)

Base fonctionnelle d'une alternative à TryHackMe, conçue pour être **gratuite**
et **portable sur tout système** grâce à Docker. Deux parcours dès le départ :
**Pentest** (machines vulnérables à attaquer) et **Analyse SOC** (investigation
sur des journaux/artefacts).

> Ce dépôt est un MVP réel et fonctionnel, pas une maquette. Il pose les
> fondations ; la feuille de route ci-dessous indique ce qu'il reste à bâtir
> pour égaler une plateforme commerciale.

## Pourquoi cette architecture

La partie difficile (et coûteuse) d'une plateforme type TryHackMe n'est pas le
site : c'est l'infrastructure qui démarre des **machines isolées à la demande**.
TryHackMe loue des VM dans le cloud — incompatible avec « gratuit ».

Le compromis retenu : les machines de labo sont des **conteneurs Docker locaux**
lancés à la demande. Avantages : zéro coût cloud, et `docker compose up`
fonctionne à l'identique sous **Windows, macOS et Linux**. C'est ça, la
portabilité.

## Démarrage rapide

Prérequis : Docker + Docker Compose installés.

```bash
# 1) Construire l'image de la machine vulnérable (parcours pentest)
docker build -t cyberlab/pentest-webapp:latest ./labs/pentest-webapp

# 2) Lancer la plateforme
docker compose up --build
```

- Interface : http://localhost:8080
- API : http://localhost:8000 (documentation auto : http://localhost:8000/docs)
- Compte démo admin : `admin` / `admin1234`

Le parcours **SOC** ne nécessite aucune machine : ouvrez `labs/soc-log-analysis/`
et analysez `auth.log` (commandes fournies dans son README).

## Architecture

```
Navigateur ──> Frontend (Nginx, SPA :8080)
                   │  appels REST
                   ▼
              API FastAPI (:8000) ── SQLite (volume persistant)
                   │  via /var/run/docker.sock
                   ▼
        Machines de labo = conteneurs Docker jetables
        (réseau dédié, CPU/RAM limités, capacités retirées)
```

- **backend/** — API FastAPI : comptes (JWT), rooms, tâches, validation de
  flags **côté serveur** (le flag n'est jamais envoyé au navigateur), points,
  classement, cycle de vie des machines de labo (`lab_engine.py`).
- **frontend/** — SPA d'un seul fichier (HTML/JS, sans build) : catalogue de
  labos, console « Démarrer la machine », soumission de flags, profil, classement.
- **labs/** — contenu pédagogique :
  - `pentest-webapp/` : appli web volontairement vulnérable (injection SQL) ;
  - `soc-log-analysis/` : jeu de logs + questions d'investigation.

## Sécurité (à connaître)

- Les machines de labo tournent avec `cap_drop: ALL` et `no-new-privileges`,
  CPU/RAM bridés, sur un réseau Docker isolé.
- Le montage de `docker.sock` donne des droits élevés à l'API : **acceptable en
  usage perso/équipe de confiance**, à remplacer par un orchestrateur dédié
  (Kubernetes + politiques réseau, ou un service de provisioning séparé) pour
  un déploiement public multi-utilisateurs.
- Changez `SECRET_KEY` et le mot de passe admin avant toute mise en ligne.

## Feuille de route (du MVP à la plateforme complète)

Phase 1 — fait : auth, rooms pentest+SOC, flags, points, classement, machine
à la demande, portabilité Docker.

Phase 2 — contenu & confort :
- éditeur d'admin pour créer des rooms sans toucher au code ;
- rendu Markdown des consignes, indices déblocables coûtant des points ;
- plus de labos (XSS, IDOR, escalade de privilèges Linux ; côté SOC : analyse
  PCAP avec Wireshark/Zeek, requêtes Splunk/Elastic, malware triage).

Phase 3 — montée en charge multi-utilisateurs :
- isolation réseau par utilisateur (un sous-réseau par session) ;
- file d'attente / quotas de machines, expiration automatique ;
- provisioning hors `docker.sock` (agent dédié ou Kubernetes) ;
- VPN (WireGuard) pour exposer les machines comme sur TryHackMe.

Phase 4 — communauté :
- badges, streaks, parcours guidés, rooms communautaires, mode équipe/classes.

## Réutiliser l'existant plutôt que tout réécrire

Pour accélérer, on peut intégrer des briques open source éprouvées :
- **CTFd** (moteur de challenges/flags très complet) ;
- **OWASP Juice Shop**, **DVWA**, **VulnHub** (cibles vulnérables prêtes) ;
- **Security Onion**, **Wazuh**, **TheHive**, **Velociraptor** (parcours SOC/DFIR) ;
- **Wireshark/Zeek**, **Sigma**, **MITRE ATT&CK Navigator** (analyse & cadrage).

## Pile technique

FastAPI · SQLAlchemy · SQLite (→ PostgreSQL en prod) · JWT (bcrypt) ·
Docker SDK · Nginx · JS vanilla. Aucune dépendance payante.
