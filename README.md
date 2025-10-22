# ⚙️ CrackEnv
CrackEnv — Outil d'audit local pour détecter et formater les fuites de .env (DB, SMTP, AWS, Stripe, Shopify) — usage éthique seulement.



# ⚙️ CrackEnv

**CrackEnv** est un outil d’audit local en **Python** permettant d’analyser une liste de domaines ou d’adresses IP pour détecter la présence de fichiers `.env` exposés.  
Il identifie et formate automatiquement les fuites potentielles de **bases de données**, **SMTP**, **AWS**, **Stripe**, et **Shopify**.

> ⚠️ **Usage Éthique et Légal Uniquement**  
> Cet outil est destiné à l’audit de sécurité **autorisé**.  
> L’utilisation sur des systèmes sans permission explicite est **illégale** et **strictement interdite**.  
> En utilisant ce programme, vous acceptez de l’utiliser uniquement sur des infrastructures que vous possédez ou pour lesquelles vous disposez d’une autorisation formelle.

---

## 🧠 Fonctionnalités

- 🔍 Analyse automatique de fichiers `.env` sur une liste d’URL.
- 📦 Extraction intelligente des sections :
  - **Base de données (DB)**
  - **SMTP (serveurs mail)**
  - **AWS (clé + secret + région)**
  - **Stripe (clé publique + secrète)**
  - **Shopify (API key, secret, scopes)**
- 🧹 Enregistre les résultats dans des dossiers dédiés :
  - `results_scan_envs/db/db.txt`
  - `results_scan_envs/smtp/smtp.txt`
  - `results_scan_envs/aws/aws.txt`
  - `results_scan_envs/stripe/stripe.txt`
  - `results_scan_envs/shopify/shopify.txt`
- 🧾 Formatte automatiquement les résultats pour une lecture claire avec `formatter.py`
- ⚡ Rapide, léger, sans proxy, basé sur `aiohttp`

---

## 🧩 Structure du projet

```
CrackEnv/
├─ crackenv_no_proxy.py      # Scanner principal (sans proxy)
├─ formatter.py              # Formatte les résultats après le scan
├─ requirements.txt          # Dépendances Python
├─ README.md                 # Documentation
├─ LICENSE                   # Licence MIT
├─ .gitignore
└─ results_scan_envs/
   ├─ db/
   ├─ smtp/
   ├─ aws/
   ├─ stripe/
   └─ shopify/
   
```
---

## 🧰 Technologies utilisées

- 🐍 **Python 3.8+**
- 🌐 **aiohttp** – pour les requêtes HTTP asynchrones rapides
- 🧠 **Regex** – pour détecter les variables sensibles dans les fichiers `.env`
- 📁 **Système de fichiers automatique** – pour trier et enregistrer les résultats dans les bons dossiers
- ⚙️ **Formatage structuré** – pour rendre les données lisibles et exploitables

---

## 🚀 Installation rapide

### 1️⃣ Cloner le dépôt
```
git clone https://github.com/TikTakkk/CrackEnv.git
cd CrackEnv
