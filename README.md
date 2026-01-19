# DNS Mapper

Outil de cartographie DNS et d'OSINT permettant d'analyser un domaine et de découvrir les relations entre domaines, sous-domaines, adresses IP et services associés.

L'objectif est de fournir une vision globale de l'infrastructure DNS d'un domaine à partir de requêtes DNS classiques et de techniques d'énumération passives.

---

## Installation

### Prérequis

- Python 3.8 ou supérieur
- Accès réseau pour effectuer des requêtes DNS
- (Optionnel) Graphviz pour la génération d'images

### Installation rapide

``ash
# Cloner le repository
git clone https://github.com/votre-username/dnspython.git
cd dnspython

# Installer les dépendances
pip install dnspython tldextract
``

### Installation pour les développeurs

``ash
pip install dnspython tldextract black flake8 pytest pytest-cov
``

---

## Utilisation

### Utilisation basique

``ash
# Analyser un domaine
python dns_mapper.py example.com

# Mode interactif
python dns_mapper.py
``

### Options

``ash
# Afficher les données brutes
python dns_mapper.py example.com --raw

# Générer un graphique
python dns_mapper.py example.com --graphviz diagram.dot
``

---

## Fonctionnalités

- Résolution DNS IPv4 et IPv6 (A / AAAA)
- Reverse DNS (PTR)
- Découverte de voisins IP (IP -1 / IP +1)
- Analyse des enregistrements MX, NS, SRV, CNAME
- Extraction de domaines depuis TXT (SPF)
- Énumération de sous-domaines courants
- Détection des domaines parents
- Export Graphviz avec conversion JPG

---

## Tests

### Lancer les tests

``ash
pytest tests/
``

### Vérifier la qualité du code

``ash
# Formatage (black)
black dns_mapper.py

# Style (flake8)
flake8 dns_mapper.py
``

---

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les instructions.

``ash
# Installation dev
pip install dnspython tldextract black flake8 pytest pytest-cov

# Formater le code
black dns_mapper.py

# Vérifier le style
flake8 dns_mapper.py

# Lancer les tests
pytest tests/
``

---

## Licence

MIT License - Voir LICENSE pour les détails
