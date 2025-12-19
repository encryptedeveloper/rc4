# 🔐 RC4 Encryption/Decryption Tool

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![RC4](https://img.shields.io/badge/algorithm-RC4-red.svg)
![KDF Support](https://img.shields.io/badge/KDF-PBKDF2%2FEvpKDF-orange.svg)

Un outil complet de chiffrement/déchiffrement RC4 avec support KDF avancé. Compatible avec les options du site [emn178.github.io/online-tools/rc4/encrypt/](https://emn178.github.io/online-tools/rc4/encrypt/).

## ✨ Fonctionnalités

### 🔐 Chiffrement & Dérivation de clé
- **RC4 pur** - Implémentation complète KSA/PRGA
- **KDF support** - PBKDF2 (SHA1) et EvpKDF (MD5)
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
- **Compatibilité totale** avec emn178.github.io

## 📦 Installation

```bash
# Clone le repository
git clone https://github.com/encryptedeveloper/rc4.git
cd rc4

# Aucune dépendance nécessaire - pur Python!
```

## 🚀 Utilisation rapide

### Chiffrement basique
```bash
python rc4.py "Hello World" "ma_clé"
```

### Avec KDF PBKDF2 (recommandé)
```bash
python rc4.py "Secret" "password" --kdf pbkdf2 --key-size 256 --salt-mode random
```

### Décryptage
```bash
python rc4.py "ciphertext_hex" "password" --decrypt --kdf pbkdf2 --salt-mode custom --salt "votre_sel"
```

## 🛠️ Guide complet des options

### Options principales
```
text                    Texte à traiter (stdin si vide)
key                     Clé/passphrase de chiffrement
```

### 🔑 Options KDF & Clés
```
--kdf TYPE             Type KDF [pbkdf2, evpkdf, none] (défaut: pbkdf2)
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

### 🔄 Modes KDF
```bash
# PBKDF2 avec sel aléatoire (sécurisé)
python rc4.py "Confidential" "StrongPass" --kdf pbkdf2 --salt-mode random --iterations 10000

# EvpKDF avec sel personnalisé
python rc4.py "Data" "Key123" --kdf evpkdf --salt-mode custom --salt "MyUniqueSalt"

# Sans KDF (clé brute - compatible legacy)
python rc4.py "Text" "rawkey" --kdf none --salt-mode none
```

### 🎯 Scénarios pratiques
```bash
# Chiffrement fichier avec KDF
python rc4.py --input-file document.txt --key "master_password" \
  --kdf pbkdf2 --salt-mode random --output-file document.enc

# Décryptage fichier
python rc4.py --input-file document.enc --key "master_password" --decrypt \
  --kdf pbkdf2 --salt-mode custom --salt "53616c7465645f5f3de48688b706620ed2e3" \
  --output-file document_decrypted.txt

# Pipeline avec données hex
echo -n "48656c6c6f" | python rc4.py --key "test" --input-encoding hex --drop 2

# Batch processing
for file in *.txt; do
  python rc4.py --input-file "$file" --key "batch_key" --kdf evpkdf \
    --output-file "${file%.txt}.rc4" --salt-mode random
done
```

### ✅ Tests de compatibilité
```bash
# Vérification avec le site web
python rc4.py "test" "key" --kdf none --salt-mode none
# Devrait retourner: bf0b0c (identique au site)

# Test KDF
python rc4.py "Hello" "world" --kdf pbkdf2 --salt-mode custom --salt "test" --iterations 1
```

## 🛡️ Sécurité & KDF

### PBKDF2 (Password-Based Key Derivation Function 2)
- **Algorithme** : HMAC-SHA1
- **Avantages** : Standardisé, résistant aux attaques
- **Utilisation** : `--kdf pbkdf2 --iterations 10000`

### EvpKDF (EVP Key Derivation Function)
- **Algorithme** : MD5 itéré
- **Avantages** : Compatible CryptoJS, rapide
- **Utilisation** : `--kdf evpkdf`

### Gestion des sels
| Mode | Description | Usage |
|------|-------------|--------|
| `random` | Génère un sel sécurisé aléatoire | Pour nouveaux chiffrements |
| `custom` | Utilise un sel spécifié | Pour déchiffrement ou sel connu |
| `none` | Pas de sel | Compatibilité legacy |

**Important** : Conservez le sel généré avec `--salt-mode random` pour pouvoir déchiffrer plus tard!

## ⚠️ Dépannage

### Problèmes courants
```bash
# Erreur: "Impossible de supprimer X octets"
python rc4.py "short" "key" --drop 10  # Trop grand pour les données

# Erreur: "Non-hexadecimal digit found"
python rc4.py "invalid hex" "key" --input-encoding hex  # Nettoyer l'entrée hex

# Décryptage échoue
# → Vérifiez: même clé, même KDF, même sel, mêmes paramètres
```

### Vérification des paramètres
```bash
# Affiche les infos KDF
python rc4.py "test" "pass" --kdf pbkdf2 --salt-mode random
# Notez le sel affiché pour déchiffrement futur
```

## 📊 Structure du projet
```
rc4/
├── rc4.py              # Script principal
├── LICENSE             # Licence MIT
└── README.md           # Documentation
```

## 🔄 Workflow recommandé

1. **Chiffrement avec sel aléatoire**
   ```bash
   python rc4.py "Mon secret" "MaPassphrase" --kdf pbkdf2 --salt-mode random
   ```

2. **Conserver les informations affichées**
   ```
   [Info] KDF: PBKDF2, Taille clé: 128 bits
   [Info] Mode sel: random
   [Info] Sel utilisé: 53616c7465645f5f3de48688b706620ed2e3
   [Info] Itérations: 1000
   ```

3. **Décryptage avec mêmes paramètres**
   ```bash
   python rc4.py "ciphertext" "MaPassphrase" --decrypt \
     --kdf pbkdf2 --salt-mode custom --salt "53616c7465645f5f3de48688b706620ed2e3"
   ```

## 🤝 Contribution

Les contributions sont bienvenues! Processus:
1. Fork le projet
2. Créez une branche feature (`git checkout -b feature/Amelioration`)
3. Commitez (`git commit -m 'Ajout: Description'`)
4. Push (`git push origin feature/Amelioration`)
5. Ouvrez une Pull Request

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE) pour détails.

## ⚠️ Avertissement de sécurité

**RC4 est considéré comme cryptographiquement faible** et ne devrait pas être utilisé pour:
- Données sensibles
- Communications sécurisées
- Conformité aux standards modernes

**Utilisez ce tool pour:**
- Compatibilité legacy
- Apprentissage cryptographique
- Applications non-critiques

## 🌟 Support

Si ce projet vous est utile:
- Donnez une ⭐ sur GitHub
- Signalez les bugs via Issues
- Proposez des améliorations

---

**Développé avec ❤️ pour la communauté crypto - [@encryptedeveloper](https://github.com/encryptedeveloper)**
