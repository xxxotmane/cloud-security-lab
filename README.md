# Lab de sécurité Cloud : observer, auditer et interpréter

Ce dépôt présente mon laboratoire réalisé en cinquième année de génie informatique, option cybersécurité. J’ai utilisé Nmap, OWASP ZAP et Prowler pour regarder un environnement sous trois angles : les services réseau accessibles, la configuration d’une application web et les protections des ressources Cloud.

Mon objectif était aussi d’apprendre à lire les résultats avec recul. Un port ouvert n’est pas automatiquement une faille, et un résultat `FAIL` n’est pas une preuve d’exploitation. Les observations ci-dessous proviennent de mon laboratoire du 12 octobre 2026. Les corrections proposées n’ont pas été appliquées ni validées par un second audit.

## Fichiers du dépôt

- [Compte rendu PDF de 3 pages](docs/rapport-lab.pdf) et [version modifiable](docs/rapport-lab.md).
- [Captures des manipulations](assets/) sans jeton ni mot de passe.
- [Synthèse des résultats](results/summary.json) et [résultats Prowler sélectionnés](results/prowler-findings.csv), avec le compte fictif LocalStack.

## Environnement et périmètre

| Composant | Installation utilisée | Rôle |
|---|---|---|
| Windows 11 / PowerShell | Poste de travail | Exécution des commandes |
| Docker Desktop | Moteur Linux | Exécution des conteneurs |
| AWS CLI | Version 2 | Vérifications manuelles |
| Nmap | 7.991, avec Npcap | Découverte des ports et services |
| LocalStack | 2026.9.1 | Simulation des API AWS |
| OWASP Juice Shop | Image Docker | Application volontairement vulnérable |
| OWASP ZAP | Image `stable` | Scan baseline |
| Prowler | 5.44.0, image Docker | Audit S3 et IAM |

Les scans réseau ont porté sur la cible d’entraînement `scanme.nmap.org` et sur mon poste. Les analyses web et Cloud ont ciblé mes conteneurs. Pour reproduire le travail, utiliser uniquement ces ressources de laboratoire et respecter les [conditions de scan de Nmap](https://nmap.org/book/legal-issues.html). Les ports des applications locales sont publiés sur `127.0.0.1`.

## Reproduire le laboratoire avec PowerShell

Docker Desktop, AWS CLI v2, Nmap et un compte LocalStack avec un jeton valide sont nécessaires. Exécuter les commandes dans l’ordre depuis la racine du dépôt, dans la même fenêtre PowerShell. Cette procédure suppose que les conteneurs `localstack` et `juice-shop`, ainsi que le réseau `tp2-reseau`, n’existent pas encore.

### 1. Démarrer les services

```powershell
docker network create tp2-reseau
```

Saisir le jeton uniquement quand le terminal le demande. Ne pas remplacer le texte de l’invite ni les guillemets vides de la seconde ligne.

```powershell
$jeton = Read-Host "Colle ton jeton LocalStack" -AsSecureString
$env:LOCALSTACK_AUTH_TOKEN = [System.Net.NetworkCredential]::new("", $jeton).Password
docker run -d --name localstack -p 127.0.0.1:4566:4566 -e LOCALSTACK_AUTH_TOKEN localstack/localstack
docker network connect tp2-reseau localstack
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker network connect tp2-reseau juice-shop
docker ps
```

Attendre que LocalStack soit prêt, puis vérifier son API et ouvrir la boutique :

```powershell
Invoke-RestMethod -Uri "http://localhost:4566/_localstack/health"
Start-Process "http://localhost:3000"
```

### 2. Préparer les ressources simulées

```powershell
$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION = "eu-west-3"
$env:AWS_ENDPOINT_URL = "http://localhost:4566"
aws --endpoint-url http://localhost:4566 sts get-caller-identity
aws --endpoint-url http://localhost:4566 s3 mb s3://tp-cloud-otmane
```

`test` est un identifiant fictif pour LocalStack. Ce n’est pas le jeton d’activation du produit. Sous PowerShell, `$env:` remplace le `export` des commandes Linux.

### 3. Observer le réseau

```powershell
nmap scanme.nmap.org
nmap -sV -p 22,25,80,443 scanme.nmap.org
nmap -sV -p- scanme.nmap.org
nmap -sV -p 4566 127.0.0.1
```

`-sV` tente d’identifier les services ; `-p-` couvre les ports TCP 1 à 65535. Le scan complet est le plus long. Éviter de le relancer inutilement.

### 4. Analyser Juice Shop

```powershell
$rapportDir = Join-Path $PWD.Path "reports\zap"
New-Item -ItemType Directory -Path $rapportDir -Force
docker run --rm --network tp2-reseau -v "${rapportDir}:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://juice-shop:3000 -r rapport-zap.html
Invoke-Item "$rapportDir\rapport-zap.html"
```

Le [baseline ZAP](https://www.zaproxy.org/docs/docker/baseline-scan/) explore des pages et analyse passivement les réponses, sans scan actif d’exploitation. Un code de sortie `2` peut correspondre à des avertissements détectés, avec un rapport correctement généré. Dans le conteneur, `localhost` désignerait ZAP lui-même ; le réseau Docker permet d’utiliser le nom `juice-shop`.

### 5. Auditer S3 et IAM

```powershell
$prowlerDir = Join-Path $PWD.Path "reports\prowler"
New-Item -ItemType Directory -Path $prowlerDir -Force
docker run --rm --network tp2-reseau -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_DEFAULT_REGION=eu-west-3 -e AWS_ENDPOINT_URL=http://localstack:4566 -e AWS_EC2_METADATA_DISABLED=true -v "${prowlerDir}:/output:rw" prowlercloud/prowler:stable aws --service s3 iam --region eu-west-3 --output-formats html csv --output-directory /output
```

Cette connexion par `AWS_ENDPOINT_URL` a fonctionné avec Prowler 5.44.0. L’aide de cette version ne proposait pas `--endpoint-url`. L’installation locale par `pip`, sous Python 3.14, échouait au démarrage avec une erreur Pydantic ; j’ai donc utilisé Docker.

## Résultats observés

### Réseau : trois ports ouverts au scan complet

Le premier scan ciblait `50.116.1.184` et affichait quatre ports ouverts : 22, 25, 80 et 443. Les scans suivants ont utilisé `45.33.32.156`. Cette différence d’adresse empêche de conclure à une modification des services sur une même machine.

Le scan complet de `45.33.32.156`, terminé en 788,29 secondes, a trouvé **3 ports ouverts**, **65 513 fermés** et **19 filtrés** :

| Port ouvert | Identification Nmap |
|---|---|
| 22 | OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 |
| 80 | Apache httpd 2.4.7 |
| 9929 | Nping echo |

Les versions sont des indications à vérifier, pas une preuve de vulnérabilité. Localement, le port 4566 était ouvert avec `TwistedWeb httpd 26.4.0`. Le scan de boucle locale ne démontre aucune exposition à Internet.

### Web : dix types d’alertes

ZAP a découvert **116 URL**. Le rapport HTML comptait **2 alertes moyennes, 4 faibles et 4 informatives**, sans alerte élevée. J’ai retenu trois observations :

| Alerte | Preuve et interprétation |
|---|---|
| CSP absente — Moyen | Absence de `Content-Security-Policy`, notamment sur la page principale et `/ftp`. Il manque une protection contre certaines injections ; aucune XSS n’a été démontrée. |
| Cross-Domain Misconfiguration — Moyen | `Access-Control-Allow-Origin: *` sur des fichiers publics JavaScript, CSS et `robots.txt`. La lecture entre origines est autorisée, sans fuite de données sensibles démontrée. |
| Feature Policy obsolète — Faible | Présence de `Feature-Policy`. Une migration adaptée vers `Permissions-Policy` est recommandée. |

### Cloud : interpréter les écarts

Prowler a exécuté **73 contrôles** en **16,1 secondes**, produisant **33 résultats : 19 FAIL et 14 PASS**. Les échecs concernaient IAM (10) et S3 (9), avec 11 résultats moyens et 8 faibles.

Le bucket était signalé comme privé et chiffré en AES256, mais sans versioning ni journalisation des accès. La politique IAM ne satisfaisait pas l’exigence de longueur minimale de 14 caractères. Le `FAIL` SSE-KMS ne signifiait pas absence de chiffrement : la règle demandait une gestion des clés différente de SSE-S3.

Vérifications manuelles :

```powershell
aws --endpoint-url http://localhost:4566 s3api get-bucket-versioning --bucket tp-cloud-otmane
aws --endpoint-url http://localhost:4566 s3api get-bucket-encryption --bucket tp-cloud-otmane
```

Après un arrêt et redémarrage sans persistance, le bucket avait disparu. La vérification a porté sur un bucket recréé : aucun état de versioning et `SSEAlgorithm: AES256`. Elle était cohérente avec l’audit précédent, mais ne portait pas sur le même état conservé. LocalStack ne permet pas de valider tous les comportements de sécurité d’AWS.

## Analyse du scénario et retour personnel

Le scénario étudié, sans exploitation réalisée, enchaînait une SSRF, la récupération d’identifiants temporaires, l’accès à un bucket public et le téléchargement de sauvegardes. Les mesures proposées sont le contrôle des destinations et redirections, la protection des métadonnées, le moindre privilège IAM et le blocage des accès publics. Un bucket réellement public constitue aussi une faiblesse indépendante : sa lecture peut ne pas nécessiter les identifiants volés.

Ce laboratoire m’a surtout appris à distinguer observation, risque et preuve. Nmap décrit une surface réseau ; ZAP signale des comportements web ; Prowler compare les configurations à des règles. Leur complémentarité aide à prioriser les vérifications, avec une analyse humaine indispensable.

## Publication et arrêt

Ce dépôt ne redistribue pas les supports du professeur. Les rapports bruts restent locaux ; les captures retenues sont dans `assets/`. Les extraits sélectionnés pour ce dépôt ne contiennent aucun jeton ni mot de passe. Les invites PowerShell visibles dans certaines captures contiennent le nom du profil Windows utilisé pendant le TP. Les tags Docker `stable` et `latest` évoluent : les résultats peuvent varier lors d’une reproduction.

```powershell
docker stop juice-shop localstack
Remove-Item Env:LOCALSTACK_AUTH_TOKEN
Remove-Variable jeton
```

L’arrêt ne supprime pas les conteneurs. La configuration Docker du conteneur conserve le jeton transmis à sa création ; ne pas publier un export ou une sortie `docker inspect` sans nettoyage. Les rapports montés dans `reports/` restent sur le poste.

Références : [LocalStack](https://docs.localstack.cloud/aws/getting-started/installation/), [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), [Prowler](https://docs.prowler.com/), [Nmap](https://nmap.org/book/).
