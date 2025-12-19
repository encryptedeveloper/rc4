# RC4 Encryption/Decryption Tool

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![RC4](https://img.shields.io/badge/algorithm-RC4-red.svg)

Un outil encore en beta de chiffrement/déchiffrement RC4.

## 🚀 Fonctionnalités

- **Chiffrement & Déchiffrement** RC4 complet
- **Multiples encodages d'entrée** : UTF-8, Hexadécimal, Base64
- **Formats de sortie** : Hex (minuscule/majuscule), Base64
- **Option "Drop bytes"** : Supprime N premiers octets du résultat
- **Support fichiers** : Lecture/écriture depuis/vers des fichiers
- **Interface CLI intuitive** avec arguments détaillés
- **Compatibilité totale** avec le site emn178.github.io
- **Support stdin/stdout** pour intégration dans des pipelines

## 📦 Installation

```bash
# Clone le repository
git clone https://github.com/encryptedeveloper/rc4.git
cd rc4
```

## 🛠️ Utilisation

### Encryptage basique
```bash
python rc4.py "Hello World" "ma_clé"
```

### Encryptage avec options avancées
```bash
# Hex → Hex majuscule avec suppression de 3 octets
python rc4.py "48656c6c6f" "secret" --input-encoding hex --output-encoding hex_upper --drop 3

# Base64 → Base64
python rc4.py "SGVsbG8gV29ybGQ=" "key" --input-encoding base64 --output-encoding base64
```

### Décryptage
```bash
# Hex → UTF-8
python rc4.py "7f7c7b7a79" "secret" --decrypt --input-encoding hex
```

### Avec fichiers
```bash
# Encryptage fichier
python rc4.py --input-file message.txt --key "password" --output-file encrypted.txt

# Décryptage fichier
python rc4.py --input-file encrypted.txt --key "password" --decrypt --output-file decrypted.txt
```

### Pipeline avec stdin
```bash
echo -n "Secret Message" | python rc4.py --key "mykey"
cat message.txt | python rc4.py --key "pass" --output-encoding base64
```

## 📋 Options disponibles

### Arguments principaux
```
text                    Texte à encrypter (lecture stdin si absent)
key                     Clé de chiffrement
```

### Options d'encodage
```
--input-encoding       Encodage entrée [utf8, hex, base64] (défaut: utf8)
--output-encoding      Encodage sortie [hex_lower, hex_upper, base64, raw] (défaut: hex_lower)
```

### Options de traitement
```
--decrypt              Mode déchiffrement
--drop N               Supprime N premiers octets du résultat
```

### Options fichiers
```
--input-file FILE      Lit l'entrée depuis un fichier
--output-file FILE     Écrit la sortie dans un fichier
--key KEY              Spécifie la clé (alternative)
```

## 🔧 Exemples détaillés

### Exemple 1 : Compatibilité avec le site web
```bash
# Sur le site : Texte="test", Clé="key", Output=hex lowercase
# Résultat attendu : bf0b0c

python rc4.py "test" "key"
# Sortie : bf0b0c ✓
```

### Exemple 2 : Drop bytes
```bash
# Supprime les 2 premiers octets du résultat encrypté
python rc4.py "message" "secret" --drop 2
```

### Exemple 3 : Sortie en majuscules
```bash
python rc4.py "data" "key123" --output-encoding hex_upper
# Sortie : 1A2B3C4D (au lieu de 1a2b3c4d)
```

### Exemple 4 : Traitement par lots
```bash
# Encrypte plusieurs fichiers
for file in *.txt; do
    python rc4.py --input-file "$file" --key "master_key" --output-file "${file%.txt}.enc"
done
```

## 🧪 Tests de validation

Vérifiez la compatibilité avec le site :
```bash
# Test 1
python rc4.py "RC4" "test" --output-encoding hex_upper
# Doit correspondre au site avec mêmes paramètres

# Test 2
python rc4.py "Hello" "world" --input-encoding hex --output-encoding base64
# Vérifiez sur le site avec input hex de "Hello"
```

## 🐛 Dépannage

### Erreur "Impossible de supprimer X octets"
```
Solution : Réduisez la valeur de --drop ou vérifiez la taille de vos données
```

### Erreur "Non-hexadecimal digit found"
```
Solution : Nettoyez l'entrée hex (pas d'espaces, retours à la ligne)
```

### Caractères spéciaux UTF-8
```
Solution : Utilisez des guillemets pour les chaînes complexes
python rc4.py "Mot de passé €uro" "clé_secrète"
```

## 📁 Structure du projet

```
rc4-tool/
├── rc4.py              # Script principal
├── README.md           # Ce fichier
├── examples/           # Exemples d'utilisation
│   ├── test_vectors.txt
│   └── batch_encrypt.sh
└── tests/              # Tests unitaires
    └── test_rc4.py
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Fork le projet
2. Créez une branche (`git checkout -b feature/AmazingFeature`)
3. Commitez vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📄 Licence

Distribué sous licence MIT. Voir `LICENSE` pour plus d'informations.

## 🔗 Liens utiles

- [Documentation RC4 sur Wikipedia](https://fr.wikipedia.org/wiki/RC4)
- [Standard de chiffrement RC4](https://tools.ietf.org/html/rfc6229)

## ⭐ Support

Si ce projet vous est utile, n'hésitez pas à :
- Donner une ⭐ sur GitHub
- Partager avec vos collègues
- Signaler les bugs ou suggestions d'amélioration

---

**Note** : RC4 est considéré comme faible pour les applications de sécurité modernes. Utilisez-le uniquement pour de la compatibilité héritée ou des applications non-critiques.

**Made with ❤️ pour la communauté crypto**
