
# DNS Mapper

Outil de reconnaissance d'infrastructure et de cartographie topologique DNS. Ce script automatise la collecte d'enregistrements DNS, la découverte de sous-domaines, l'identification de voisins IP et la génération de graphiques relationnels.

## Architecture du Code

Le flux d'exécution se divise en trois phases : Collecte, Agrégation et Rendu.

```text
+----------------+       +-----------------------------------------+
|  Entrée (CLI)  | ----> |           Moteur de Résolution          |
|     Domaine    |       |         (dnspython / tldextract)        |
+----------------+       +--------------------+--------------------+
                                              |
          +-----------------------------------+-----------------------------------+
          |                                   |                                   |
  [Résolution Directe]                [Énumération]                       [Pivot IP]
  - A / AAAA (IPs)                    - Brute-force (list)                - Reverse DNS (PTR)
  - MX, NS, TXT, SRV                  - Extraction TLD                    - Scan Voisins (+/- 1)
  - CNAME aliases                     - Parsing TXT regex
          |                                   |                                   |
          +-----------------------------------+-----------------------------------+
                                              |
                                     +--------v--------+
                                     |   Agrégation    |
                                     |  & Corrélations |
                                     +--------+--------+
                                              |
                    +-------------------------+-------------------------+
                    |                                                   |
          +---------v----------+                              +---------v---------+
          |  Rapport Console   |                              |  Moteur Graphique |
          | (Texte Structuré)  |                              |    (Graphviz)     |
          +--------------------+                              +---------+---------+
                                                                        |
                                                                  [Fichier .DOT]
                                                                        |
                                                                  [Rendu .JPG]
```

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

Lancer le script via l'interpréteur Python. Si aucun argument n'est fourni, le script demandera le domaine de manière interactive.

```bash
python dns_mapper.py [domaine] [options]
```

### Options Disponibles

| Argument | Description |
|----------|-------------|
| `domain` | Le domaine cible (ex: google.com). |
| `--graphviz FILE` | Chemin de sortie personnalisé pour le fichier .dot (défaut: domaine_diagram.dot). |
| `--all` | Affiche toutes les sections dans la console. |
| `--ips` | Affiche uniquement les IPs résolues. |
| `--subdomains` | Affiche uniquement les sous-domaines découverts. |
| `--records` | Affiche les enregistrements MX, NS et TXT. |
| `--neighbors` | Affiche les voisins IP détectés via pivot. |
| `--cname` | Affiche les redirections CNAME. |
| `--srv` | Affiche les services SRV détectés. |
| `--parents` | Affiche la hiérarchie des domaines parents. |

### Exemple

Exécuter une analyse complète et générer le graphe :

```bash
python dns_mapper.py oracle.com --all
```

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

Pour v�rifier la qualit� du code :

```bash
.venv/Scripts/flake8.exe dns_mapper.py && .venv/Scripts/pylint.exe dns_mapper.py
```
