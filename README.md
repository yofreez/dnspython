# DNS Mapper

Outil de reconnaissance d'infrastructure et de cartographie topologique DNS. Ce script automatise la collecte d'enregistrements DNS, la découverte de sous-domaines, l'identification de voisins IP et la génération de graphiques relationnels.

## Architecture du Code

Le flux d'exécution suit une approche **DRY** (Don't Repeat Yourself) avec configuration centralisée :

```text
┌──────────────────────────────────────────────────────────────────────┐
│                        CLI - Argparse                                │
│   (--domain --scan N --subs --mx --ns --ips --reverse --all ...)   │
└──────────────────────┬───────────────────────────────────────────────┘
                       │
        ┌──────────────v──────────────┐
        │   scan(domain, depth)       │
        │  Boucle BFS récursive       │
        └──────────────┬──────────────┘
                       │
     ┌─────────────────┼─────────────────┐
     │                 │                 │
[Configuration]   [Exécution]      [Résultats]
domain_scanners   Boucle queue      dictionary
(tuples)          while queue       {IPs, MX, NS,
                                     SRV, TXT,
                                     CNAME...}
     │                 │                 │
     └─────────────────┼─────────────────┘
                       │
        ┌──────────────v──────────────┐
        │  generate_markdown()        │
        │  Filtrage dynamique         │
        │  (show_all logic)           │
        └──────────────┬──────────────┘
                       │
        ┌──────────────v──────────────┐
        │  export_graphviz()          │
        │  Config styles centralisée  │
        │  (styles tuple list)        │
        └──────────────┬──────────────┘
                       │
      ┌────────────────┴────────────────┐
      │                                 │
 [Fichier .DOT]                   [Compilation]
 Graphviz DOT                     dot.exe
      │                                 │
      └────────────────┬────────────────┘
                       │
                  [JPG Output]
```

**Principes d'optimisation :**
- **Configuration centralisée** : `domain_scanners` et `styles` comme listes de tuples
- **Boucles unifiées** : Une seule boucle pour exécuter/traiter tous les scanners
- **Filtrage intelligent** : Logique `show_all` pour décider dynamiquement quoi afficher
- **Code maintenable** : Ajouter un nouveau scanner = 1 ligne dans la config

## Pré-requis

### Dépendances Python

Le script nécessite les bibliothèques suivantes :

- **dnspython** : Pour les requêtes DNS.
- **tldextract** : Pour l'analyse syntaxique des domaines.

```bash
pip install dnspython tldextract
```

### Dépendances Système (Graphviz)

Pour la génération des images JPG, le logiciel Graphviz doit être installé sur le système hôte.

- **Windows** : Installer Graphviz et s'assurer que `dot.exe` est accessible. Le script tente de le localiser automatiquement dans les répertoires standards (`C:\Program Files`).
- **Linux/Mac** : `sudo apt install graphviz` ou `brew install graphviz`.

## Utilisation

Lancer le script avec un domaine cible. Le rapport Markdown et le diagramme Graphviz sont générés automatiquement.

```bash
python dns_mapper.py <domaine> [options]
```

### Options Disponibles

| Argument | Type | Description |
|----------|------|-------------|
| `domain` | Positional | Le domaine cible (ex: google.com) **obligatoire** |
| `--scan N` | int | Profondeur du scan récursif (défaut: 100) |
| `--graphviz FILE` | str | Chemin de sortie personnalisé pour le fichier .dot |
| `--subs` | flag | Afficher les sous-domaines découverts |
| `--mx` | flag | Afficher les enregistrements MX (mail) |
| `--ns` | flag | Afficher les enregistrements NS (name servers) |
| `--srv` | flag | Afficher les enregistrements SRV (services) |
| `--txt` | flag | Afficher les enregistrements TXT |
| `--cname` | flag | Afficher les redirections CNAME (aliases) |
| `--parents` | flag | Afficher la hiérarchie des domaines parents |
| `--ips` | flag | Afficher les adresses IP résolues (A/AAAA) |
| `--reverse` | flag | Afficher les résolutions reverse DNS (PTR) |
| `--neighbors` | flag | Afficher les voisins IP (±1) |
| `--all` | flag | Afficher **tous** les résultats (prime sur les filtres) |

### Comportement du filtrage

- **Sans arguments** → Affiche **tout** (comportement par défaut)
- **Avec flags spécifiques** → Affiche **seulement ce qui est demandé**
- **Avec `--all`** → Affiche **tout** (override les filtres spécifiques)

### Exemples

**Analyse complète (affiche tout) :**
```bash
python dns_mapper.py oracle.com
# ou
python dns_mapper.py oracle.com --all
```

**Filtré : IPs et reverse DNS seulement :**
```bash
python dns_mapper.py oracle.com --ips --reverse
```

**Scan avec profondeur limitée :**
```bash
python dns_mapper.py oracle.com --scan 10
```

**Sous-domaines et MX avec profondeur 20 :**
```bash
python dns_mapper.py oracle.com --scan 20 --subs --mx
```

**Tous les enregistrements :**
```bash
python dns_mapper.py oracle.com --all --graphviz custom_output.dot
```

### Sortie

Chaque exécution génère :
- **`{domaine}_report.md`** : Rapport Markdown structuré avec toutes les données DNS
- **`{domaine}_map.dot`** : Fichier Graphviz (DOT format)
- **`{domaine}_map.jpg`** : Diagramme visuel compilé (si Graphviz est installé)

## Fonctionnalités Techniques

### Résolution DNS

Support complet des enregistrements A, AAAA, MX, NS, TXT, SRV, CNAME et PTR.

### Découverte de Sous-domaines

- Dictionnaire statique de préfixes courants (www, api, mail, etc.).
- Extraction via expressions régulières (Regex) dans les enregistrements TXT.

### Pivot IP

Analyse des adresses IP adjacentes (+1 / -1) pour découvrir des hôtes voisins hébergés sur le même sous-réseau.

### Visualisation

Génération automatique d'un diagramme vectoriel (DOT) et matriciel (JPG) représentant la topologie de l'infrastructure.

- **Moteur** : Graphviz.
- **Style** : `rankdir=LR` (Gauche à Droite), `splines=curved` (Lignes courbes).
- **Code couleur** : Différenciation visuelle des IPs, sous-domaines, records et voisins.

## Linter

Pour vérifier la qualité du code :

```powershell
.venv/Scripts/flake8.exe dns_mapper.py; .venv/Scripts/pylint.exe dns_mapper.py; .venv/Scripts/mypy.exe dns_mapper.py
```
