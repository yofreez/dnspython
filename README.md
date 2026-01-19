# DNS Mapper

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

DNS Mapper est un outil de cartographie DNS et d'OSINT permettant d'analyser un domaine et de découvrir les relations entre domaines, sous-domaines, adresses IP et services associés.

L'objectif est de fournir une vision globale de l'infrastructure DNS d'un domaine à partir de requêtes DNS classiques et de techniques d'énumération passives.

---

## 📋 Table des matières

- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Exemples](#exemples)
- [Architecture](#architecture)
- [Contribuer](#contribuer)
- [Tests](#tests)
- [Licence](#licence)

---

## ✨ Fonctionnalités

- ✅ Résolution DNS IPv4 et IPv6 (A / AAAA)
- ✅ Reverse DNS (PTR)
- ✅ Découverte de voisins IP (IP -1 / IP +1)
- ✅ Analyse des enregistrements MX (serveurs de messagerie)
- ✅ Analyse des enregistrements NS (serveurs de noms)
- ✅ Analyse des enregistrements SRV (SIP, LDAP, XMPP)
- ✅ Extraction de domaines depuis les enregistrements TXT (SPF, etc.)
- ✅ Énumération de sous-domaines courants
- ✅ Détection automatique des domaines parents
- ✅ Export et visualisation avec Graphviz (`.dot` et `.jpg`)
- ✅ Filtrage intelligent des résultats

---

## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- Accès réseau pour effectuer des requêtes DNS
- (Optionnel) Graphviz pour la génération d'images

### Installation rapide

```bash
# Cloner le repository
git clone https://github.com/votre-username/dnspython.git
cd dnspython

# Installer les dépendances
pip install dnspython tldextract
```

## 📖 Utilisation

### Utilisation basique

```bash
# Analyser un domaine
python dns_mapper.py example.com

# Analyser en mode interactif
python dns_mapper.py
```

### Options avancées

```bash
# Afficher les données brutes avant filtrage
python dns_mapper.py example.com --raw

# Générer un graphique personnalisé
python dns_mapper.py example.com --graphviz mon_graphique.dot
```

### Résultat

L'outil affichera :

1. **Résumé** : Nombre d'éléments découverts
2. **Adresses IP** : IPv4 et IPv6 résolues
3. **Sous-domaines** : Sous-domaines trouvés par énumération
4. **Enregistrements DNS** : MX, NS, SRV, CNAME
5. **Domaines découverts** : Depuis les TXT, MX, etc.
6. **Graphique Graphviz** : Exporté automatiquement en `.dot` et `.jpg`

---

## 💡 Exemples

### Exemple 1 : Analyse simple

```bash
$ python dns_mapper.py google.com

====================================
           DNS MAPPER
====================================

[*] Collecting data for google.com...
[+] Found 6 IP(s) | 4 subdomain(s) | 5 MX | 4 NS | 0 SRV
[+] Found 12 discovered domain(s) | 3 parent(s)

[*] Filtering data...

============================================================
DNS CARTOGRAPHY FOR GOOGLE.COM
============================================================

[SUMMARY]
  • IP Addresses: 6
  • Subdomains: 4
  • MX Records: 5
  • NS Records: 4
  ...
```

### Exemple 2 : Export Graphviz

```bash
$ python dns_mapper.py example.com --graphviz diagram.dot

[+] Graphviz file created: diagram.dot
[+] JPG generated: diagram.jpg
```

Le fichier JPG généré affiche visuellement les relations entre :
- Le domaine principal (bleu)
- Les adresses IP (rouge clair)
- Les sous-domaines (vert clair)
- Les serveurs mail (jaune)
- Les serveurs de noms (orange)

### Exemple 3 : Voir les données brutes

```bash
$ python dns_mapper.py example.com --raw

# Affiche toutes les données collectées avant filtrage
=== IPs ===
  93.184.216.34
  2606:2800:220:1:248:1893:25c8:1946
  ...
```

---

## 🏗️ Architecture

Pour comprendre la structure du projet et contribuer efficacement, consultez la [documentation d'architecture](docs/ARCHITECTURE.md).

### Structure du projet

```
dnspython/
├── dns_mapper.py          # Module principal
├── tests/
│   └── test_dns_mapper.py # Tests unitaires
├── docs/
│   └── ARCHITECTURE.md    # Documentation d'architecture
├── README.md              # Ce fichier
├── CONTRIBUTING.md        # Guide de contribution
├── requirements.txt       # Dépendances
├── requirements-dev.txt   # Dépendances de développement
├── pyproject.toml         # Configuration outils
├── .flake8               # Configuration flake8
└── .pylintrc             # Configuration pylint
```

### Composants principaux

1. **Résolution DNS** : Fonctions de base pour interroger les enregistrements
2. **Énumération** : Découverte de sous-domaines et voisins IP
3. **Filtrage** : Élimination des données non pertinentes
4. **Export** : Génération de graphiques Graphviz

---

## 🤝 Contribuer

Les contributions sont les bienvenues ! Consultez le [guide de contribution](CONTRIBUTING.md) pour démarrer.

### Quick Start pour contributeurs

1. **Fork le projet**
2. **Créer une branche** : `git checkout -b feature/ma-fonctionnalite`
3. **Installer les dépendances de dev** : `pip install -r requirements-dev.txt`
4. **Développer et tester** : `pytest tests/`
5. **Formater le code** : `black dns_mapper.py && flake8 dns_mapper.py`
6. **Commit** : `git commit -m "feat: description"`
7. **Push** : `git push origin feature/ma-fonctionnalite`
8. **Ouvrir une Pull Request**

### Domaines de contribution

- 🐛 **Bugs** : Signaler ou corriger des bugs
- ✨ **Features** : Proposer de nouvelles fonctionnalités
- 📝 **Documentation** : Améliorer la doc
- 🧪 **Tests** : Augmenter la couverture de tests
- 🎨 **UX** : Améliorer l'interface utilisateur

---

## 🧪 Tests

Le projet utilise `pytest` pour les tests unitaires.

### Exécuter les tests

```bash
# Tous les tests
pytest tests/

# Avec couverture de code
pytest tests/ --cov=dns_mapper --cov-report=html

# Tests rapides uniquement (sans réseau)
pytest tests/ -m "not integration"

# Tests spécifiques
pytest tests/test_dns_mapper.py::TestIPResolution
```

### Qualité du code

```bash
# Formatage automatique
black dns_mapper.py tests/

# Vérification du style
flake8 dns_mapper.py tests/

# Analyse statique
pylint dns_mapper.py

# Vérification des types
mypy dns_mapper.py
```

### Couverture cible

- **Couverture globale** : >80%
- **Branches critiques** : 100%

---

## 📊 Statistiques du projet

- **Lignes de code** : ~400
- **Couverture des tests** : >80%
- **Fonctions testées** : 15+
- **Standards** : PEP 8, Black, MyPy

---

## 🛠️ Technologies utilisées

- **Python 3.8+** : Langage principal
- **dnspython** : Librairie de requêtes DNS
- **tldextract** : Extraction de domaines
- **Graphviz** : Visualisation de graphes
- **pytest** : Framework de tests
- **black** : Formatage du code
- **flake8/pylint** : Linters

---

## 📝 Roadmap

### Version 1.1 (Planifié)

- [ ] Parallélisation des requêtes DNS avec `asyncio`
- [ ] Support de wordlists personnalisées pour l'énumération
- [ ] Export en JSON/CSV
- [ ] Interface web avec Flask

### Version 1.2 (Futur)

- [ ] Intégration avec des APIs OSINT (VirusTotal, Shodan)
- [ ] Détection d'anomalies DNS
- [ ] Mode stealth avec rate limiting
- [ ] Support de proxy/Tor

---

