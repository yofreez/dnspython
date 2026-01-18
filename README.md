# DNS Mapper

DNS Mapper est un outil de cartographie DNS et d’OSINT permettant d’analyser un domaine et de découvrir les relations entre domaines, sous-domaines, adresses IP et services associés.

L’objectif est de fournir une vision globale de l’infrastructure DNS d’un domaine à partir de requêtes DNS classiques et de techniques d’énumération passives.

---

## Fonctionnalités

- Résolution DNS IPv4 et IPv6 (A / AAAA)
- Reverse DNS (PTR)
- Découverte de voisins IP (IP -1 / IP +1)
- Analyse des enregistrements MX
- Analyse des enregistrements SRV (SIP, LDAP, XMPP)
- Extraction de domaines depuis les enregistrements TXT (SPF, etc.)
- Énumération simple de sous-domaines courants
- Détection des domaines parents via `tldextract`
- Export de la cartographie au format Graphviz (`.dot`)

---

## Prérequis

- Python 3.8 ou supérieur
- Accès réseau pour effectuer des requêtes DNS

### Dépendances Python

Les bibliothèques suivantes sont nécessaires :

- `dnspython`
- `tldextract`

Installation :

```bash
pip install dnspython tldextract

