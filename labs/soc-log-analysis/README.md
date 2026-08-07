# Labo SOC — Triage d'alertes : connexion suspecte

Vous êtes analyste SOC N1. Le fichier `sample-logs/auth.log` contient les
journaux d'authentification SSH d'un serveur (`srv01`). Une alerte SIEM
suggère une attaque par force brute.

## Outils de base (depuis ce dossier)
```bash
# Top des IP à l'origine d'échecs de connexion
grep "Failed password" sample-logs/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn

# Connexions RÉUSSIES (chercher une réussite depuis l'IP malveillante)
grep "Accepted password" sample-logs/auth.log
```

## Démarche d'analyse
1. Identifier la source : quelle IP génère le pic d'échecs ?
2. Évaluer l'impact : cette IP a-t-elle fini par réussir une connexion ?
3. Cadrer (MITRE ATT&CK) : la force brute = technique **T1110** (Credential Access).
4. Confiner : bloquer l'IP source, révoquer la session, forcer le reset du compte.

Répondez aux questions de la room dans l'interface pour valider et gagner des points.
