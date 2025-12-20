# 🔐 RC4 Encryption/Decryption Tool

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![RC4](https://img.shields.io/badge/algorithm-RC4-red.svg)
![KDF Support](https://img.shields.io/badge/KDF-PBKDF2%2FEvpKDF%2FHash-orange.svg)
![Hash Support](https://img.shields.io/badge/Hash-MD5%2FSHA%2FRIPEMD160-green.svg)

Un outil complet de chiffrement/déchiffrement RC4 avec support KDF et fonctions de hachage avancées.

## ✨ Fonctionnalités

### 🔐 Chiffrement & Dérivation de clé
- **RC4 pur** - Implémentation complète KSA/PRGA
- **KDF support** - PBKDF2, EvpKDF et Hash simple
- **Fonctions de hachage** - MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160
- **Gestion avancée des clés** - Tailles 40-256 bits
- **Sels intelligents** - Random, personnalisé ou aucun

### 🔄 Encodages supportés
- **Entrée** : UTF-8, Hexadécimal, Base64
- **Sortie** : Hex (minuscule/majuscule), Base64, Raw
- **Auto-détection** pour le décryptage

### ⚙️ Options avancées
- **Drop bytes** - Suppression des N premiers octets
- **Support fichiers** - Lecture/écriture directe
- **Pipeline friendly** - stdin/stdout intégration
- **Compatibilité** avec emn178.github.io (mode `--key-type none`)

## 📦 Installation

```bash
# Clone le repository
git clone https://github.com/encryptedeveloper/rc4.git
cd rc4

# Aucune dépendance nécessaire - pur Python!
```

## 🚀 Utilisation rapide

### Chiffrement basique (compatible site)
```bash
python rc4.py "Hello World" "ma_clé" --key-type none
```

### Avec hash SHA256
```bash
python rc4.py "Secret" "password" --key-type hash --hash-algo sha256
```

### Avec KDF PBKDF2 (recommandé)
```bash
python rc4.py "Secret" "password" --key-type pbkdf2 --key-size 256 --salt-mode random
```

### Décryptage
```bash
python rc4.py "ciphertext_hex" "password" --decrypt --key-type hash --hash-algo sha256
```

## 🛠️ Guide complet des options

### Options principales
```
text                    Texte à traiter (stdin si vide)
key                     Clé/passphrase de chiffrement
```

### 🔑 Options Génération de Clé
```
--key-type TYPE        Type génération [hash, pbkdf2, evpkdf, none] (défaut: pbkdf2)
--hash-algo ALGO       Algorithme hash [md5, sha1, sha224, sha256, sha384, sha512, ripemd160]
--key-size BITS        Taille clé [40,56,64,80,128,192,256] (défaut: 128)
--salt-mode MODE       Mode sel [random, custom, none] (défaut: none)
--salt VALUE           Sel personnalisé (avec --salt-mode custom)
--iterations N         Itérations PBKDF2 (défaut: 1000)
```

### 📥📤 Options encodage
```
--input-encoding       Encodage entrée [utf8, hex, base64] (défaut: utf8)
--output-encoding      Encodage sortie [hex_lower, hex_upper, base64, raw] (défaut: hex_lower)
--decrypt              Mode déchiffrement
--drop N               Supprime N premiers octets
```

### 📁 Options fichiers
```
--input-file FILE      Lit depuis un fichier
--output-file FILE     Écrit dans un fichier
```

## 📚 Exemples détaillés

### 🔄 Modes de Génération de Clé
```bash
# Hash simple SHA256 (rapide et sécurisé)
python rc4.py "Confidential" "StrongPass" --key-type hash --hash-algo sha256

# PBKDF2 avec SHA512 et sel aléatoire (très sécurisé)
python rc4.py "Data" "Key123" --key-type pbkdf2 --hash-algo sha512 --salt-mode random --iterations 10000

# EvpKDF avec MD5 (compatible legacy)
python rc4.py "Archive" "oldkey" --key-type evpkdf --hash-algo md5 --salt-mode custom --salt "legacy_salt"

# RIPEMD-160 hash
python rc4.py "Message" "secure" --key-type hash --hash-algo ripemd160

# Compatible site web (pas de KDF)
python rc4.py "Test" "simplekey" --key-type none
```

### 🎯 Scénarios pratiques
```bash
# Chiffrement fichier avec hash SHA256
python rc4.py --input-file document.txt --key "master_password" \
  --key-type hash --hash-algo sha256 --output-file document.enc

# Décryptage fichier avec mêmes paramètres
python rc4.py --input-file document.enc --key "master_password" --decrypt \
  --key-type hash --hash-algo sha256 --output-file document_decrypted.txt

# Pipeline avec données hex et sel personnalisé
echo -n "48656c6c6f" | python rc4.py --key "test" --key-type pbkdf2 \
  --input-encoding hex --salt-mode custom --salt "fixed_salt"

# Batch processing avec hash SHA384
for file in *.txt; do
  python rc4.py --input-file "$file" --key "batch_key" --key-type hash \
    --hash-algo sha384 --output-file "${file%.txt}.rc4"
done
```

## 🛡️ Sécurité & Algorithmes

### Hash Simple (--key-type hash)
- **Algorithme** : MD5, SHA-* (1/224/256/384/512), RIPEMD160
- **Avantages** : Rapide, support multiple algorithmes
- **Utilisation** : `--key-type hash --hash-algo sha256`

### PBKDF2 (--key-type pbkdf2)
- **Algorithme** : HMAC avec hash choisi
- **Avantages** : Standardisé, résistant aux attaques par force brute
- **Utilisation** : `--key-type pbkdf2 --hash-algo sha512 --iterations 10000`

### EvpKDF (--key-type evpkdf)
- **Algorithme** : Hash itératif
- **Avantages** : Compatible CryptoJS, flexible
- **Utilisation** : `--key-type evpkdf --hash-algo md5`

### Mode None (--key-type none)
- **Algorithme** : Aucune transformation
- **Avantages** : Compatible avec emn178.github.io
- **Utilisation** : `--key-type none`

### Gestion des sels
| Mode | Description | Usage |
|------|-------------|--------|
| `random` | Génère un sel sécurisé aléatoire | Sécurité maximale |
| `custom` | Utilise un sel spécifié | Déchiffrement ou sel connu |
| `none` | Pas de sel | Compatibilité legacy |

**Important** : Conservez le sel généré avec `--salt-mode random` pour pouvoir déchiffrer plus tard!

## ✅ Compatibilité

### Avec emn178.github.io
Pour une compatibilité totale avec le site [emn178.github.io/online-tools/rc4/](https://emn178.github.io/online-tools/rc4/) :
```bash
# Chiffrement compatible
python rc4.py "test" "key" --key-type none

# Décryptage compatible
python rc4.py "bf0b0c" "key" --decrypt --key-type none
```

**Note** : Les modes avec KDF ou hash (`--key-type hash/pbkdf2/evpkdf`) **ne sont pas compatibles** avec le site web, car ils offrent des fonctionnalités supplémentaires.

### 🐛 Signaler un problème de compatibilité
Si vous trouvez un cas où la sortie diffère du site avec les mêmes paramètres (`--key-type none`), merci d'ouvrir une issue sur GitHub avec :
1. Le texte d'entrée
2. La clé utilisée
3. La sortie attendue (du site)
4. La sortie obtenue (du script)

## ⚠️ Dépannage

### Problèmes courants
```bash
# Erreur: "Impossible de supprimer X octets"
python rc4.py "short" "key" --drop 10  # Trop grand pour les données

# Erreur: "Non-hexadecimal digit found"
python rc4.py "invalid hex" "key" --input-encoding hex  # Nettoyer l'entrée hex

# RIPEMD-160 non disponible
python rc4.py "test" "key" --key-type hash --hash-algo ripemd160
# → Fallback automatique vers SHA256

# Décryptage échoue
# → Vérifiez: même key-type, même hash-algo, même sel, mêmes paramètres
```

### Vérification des paramètres
```bash
# Affiche les infos complètes
python rc4.py "test" "pass" --key-type pbkdf2 --hash-algo sha512 --salt-mode random
# Notez tous les paramètres affichés pour déchiffrement futur
```

## 📊 Structure du projet
```
rc4/
├── rc4.py              # Script principal
├── LICENSE             # Licence MIT
├── README.md           # Documentation
├── .gitignore          # Fichiers ignorés
└── examples/           # Exemples (à venir)
```

## 🔄 Workflow recommandé

1. **Chiffrement avec paramètres sécurisés**
   ```bash
   python rc4.py "Mon secret" "MaPassphrase" --key-type pbkdf2 --hash-algo sha256 --salt-mode random
   ```

2. **Conserver les informations affichées**
   ```
   [Info] Type clé: PBKDF2, Hash: SHA256
   [Info] Taille clé: 128 bits
   [Info] Mode sel: random
   [Info] Sel utilisé: 53616c7465645f5f3de48688b706620ed2e3
   [Info] Itérations: 1000
   ```

3. **Décryptage avec mêmes paramètres**
   ```bash
   python rc4.py "ciphertext" "MaPassphrase" --decrypt \
     --key-type pbkdf2 --hash-algo sha256 \
     --salt-mode custom --salt "53616c7465645f5f3de48688b706620ed2e3"
   ```

## 🤝 Contribution

Les contributions sont bienvenues ! Processus :
1. Fork le projet
2. Créez une branche feature (`git checkout -b feature/Amelioration`)
3. Commitez (`git commit -m 'Ajout: Description'`)
4. Push (`git push origin feature/Amelioration`)
5. Ouvrez une Pull Request

**Pour les problèmes de compatibilité** avec emn178.github.io, ouvrez une issue avec tous les détails nécessaires.

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE) pour détails.

## ⚠️ Avertissement de sécurité

**RC4 est considéré comme cryptographiquement faible** et ne devrait pas être utilisé pour :
- Données sensibles
- Communications sécurisées
- Conformité aux standards modernes (PCI-DSS, TLS 1.2+, etc.)

**Utilisez ce tool pour :**
- Compatibilité legacy avec systèmes existants
- Apprentissage cryptographique
- Applications non-critiques
- Tests et développement

**Recommandations de sécurité :**
- Préférez `--key-type pbkdf2` avec `--hash-algo sha256` ou `sha512`
- Utilisez `--salt-mode random` pour chaque nouveau chiffrement
- Augmentez `--iterations` à 10000+ pour les données sensibles
- Conservez les sels générés en lieu sûr

## 🌟 Support

Si ce projet vous est utile :
- Donnez une ⭐ sur GitHub
- Signalez les bugs via Issues (surtout les problèmes de compatibilité)
- Proposez des améliorations ou nouvelles fonctionnalités

---

**Développé avec ❤️ pour la communauté crypto - [@encryptedeveloper](https://github.com/encryptedeveloper)**
