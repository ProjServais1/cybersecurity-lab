"""Moteur de labos : lance/arrête une machine vulnérable (conteneur Docker)
à la demande, par utilisateur. C'est l'équivalent local du bouton
« Start Machine » de TryHackMe.

Choix de conception pour la portabilité et la sécurité :
- Chaque labo tourne dans un conteneur jetable, sur un réseau Docker dédié.
- On limite CPU/RAM pour éviter qu'un labo ne sature la machine hôte.
- Un seul conteneur de labo actif par utilisateur (on coupe l'ancien).
- L'import de `docker` est paresseux : l'API démarre même sans Docker,
  utile pour les rooms 100 % SOC (analyse de logs, sans machine à lancer).
"""
import os

LAB_NETWORK = os.getenv("LAB_NETWORK", "cyberlab_labnet")
MEM_LIMIT = os.getenv("LAB_MEM_LIMIT", "512m")
CPU_QUOTA = int(os.getenv("LAB_CPU_QUOTA", "50000"))  # 0.5 CPU (sur 100000)

_client = None


def _docker():
    """Connexion paresseuse au démon Docker via le socket monté."""
    global _client
    if _client is None:
        import docker  # importé seulement quand on en a besoin
        _client = docker.from_env()
        try:
            _client.networks.get(LAB_NETWORK)
        except Exception:
            _client.networks.create(LAB_NETWORK, driver="bridge", internal=False)
    return _client


def _name(user_id: int) -> str:
    return f"cyberlab-lab-u{user_id}"


def start_lab(user_id: int, image: str, container_port: int) -> dict:
    """Démarre la machine du labo pour un utilisateur et renvoie l'URL d'accès."""
    client = _docker()
    stop_lab(user_id)  # un seul labo à la fois par utilisateur

    container = client.containers.run(
        image,
        detach=True,
        name=_name(user_id),
        network=LAB_NETWORK,
        ports={f"{container_port}/tcp": None},  # port hôte aléatoire
        mem_limit=MEM_LIMIT,
        cpu_period=100000,
        cpu_quota=CPU_QUOTA,
        cap_drop=["ALL"],                # durcissement : on retire les capacités
        security_opt=["no-new-privileges"],
        labels={"cyberlab": "1", "owner": str(user_id)},
    )
    container.reload()
    binding = container.attrs["NetworkSettings"]["Ports"].get(f"{container_port}/tcp")
    host_port = binding[0]["HostPort"] if binding else None
    return {
        "status": "running",
        "container_id": container.short_id,
        "url": f"http://localhost:{host_port}" if host_port else None,
        "host_port": host_port,
    }


def stop_lab(user_id: int) -> dict:
    client = _docker()
    try:
        c = client.containers.get(_name(user_id))
        c.remove(force=True)
        return {"status": "stopped"}
    except Exception:
        return {"status": "not_running"}


def lab_status(user_id: int) -> dict:
    client = _docker()
    try:
        c = client.containers.get(_name(user_id))
        c.reload()
        return {"status": c.status, "container_id": c.short_id}
    except Exception:
        return {"status": "not_running"}
