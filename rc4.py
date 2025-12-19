#!/usr/bin/env python3
import base64
import argparse
import sys
import hashlib
import hmac
import struct
import os
import secrets

class RC4Cipher:
    def __init__(self, key):
        self.key = key.encode() if isinstance(key, str) else key
        self.S = list(range(256))
        j = 0
        key_length = len(self.key)
        
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def process(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        i = j = 0
        result = bytearray()
        S = self.S.copy()
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result)

def pbkdf2(password, salt, key_size, iterations=1000):
    password = password.encode() if isinstance(password, str) else password
    salt = salt.encode() if isinstance(salt, str) else salt
    
    key = b''
    block_index = 1
    
    while len(key) < key_size:
        u = hmac.new(password, salt + struct.pack('>I', block_index), hashlib.sha1).digest()
        result = u
        
        for _ in range(1, iterations):
            u = hmac.new(password, u, hashlib.sha1).digest()
            result = bytes(a ^ b for a, b in zip(result, u))
        
        key += result
        block_index += 1
    
    return key[:key_size]

def evpkdf(password, salt, key_size, iterations=1):
    password = password.encode() if isinstance(password, str) else password
    salt = salt.encode() if isinstance(salt, str) else salt
    
    key = b''
    while len(key) < key_size:
        data = password + salt if len(key) == 0 else key[-len(salt):] if len(salt) > 0 else key
        for _ in range(iterations):
            md5 = hashlib.md5()
            md5.update(data)
            data = md5.digest()
        key += data
    
    return key[:key_size]

def generate_random_salt(length=16):
    return secrets.token_hex(length)

def format_salt_for_output(salt, salt_display='hex'):
    if salt_display == 'hex':
        return salt.hex() if isinstance(salt, bytes) else salt
    elif salt_display == 'base64':
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        return base64.b64encode(salt).decode('ascii')
    return salt

def derive_key(password, kdf_type='pbkdf2', key_size=128, salt='', salt_mode='custom', iterations=1000):
    key_size_bytes = key_size // 8
    
    if salt_mode == 'random':
        salt = generate_random_salt()
        print(f"[Info] Sel généré aléatoirement: {salt}")
    elif salt_mode == 'none':
        salt = ''
    elif salt_mode == 'custom':
        salt = salt
    
    if kdf_type == 'pbkdf2':
        return pbkdf2(password, salt, key_size_bytes, iterations), salt
    elif kdf_type == 'evpkdf':
        return evpkdf(password, salt, key_size_bytes, iterations), salt
    else:
        raise ValueError(f"Type KDF inconnu: {kdf_type}")

def decode_input(data, input_encoding):
    data = data.strip()
    
    if input_encoding == 'utf8':
        return data.encode('utf-8')
    elif input_encoding == 'hex':
        data = ''.join(c for c in data if c.isalnum())
        return bytes.fromhex(data)
    elif input_encoding == 'base64':
        data = ''.join(c for c in data if c.isalnum() or c in '+/=')
        return base64.b64decode(data)
    else:
        raise ValueError(f"Encodage d'entrée invalide: {input_encoding}")

def format_output(data, output_format, drop_bytes=0):
    if drop_bytes > 0:
        if drop_bytes >= len(data):
            raise ValueError(f"Impossible de supprimer {drop_bytes} octets")
        data = data[drop_bytes:]
    
    if output_format == 'hex_lower':
        return data.hex()
    elif output_format == 'hex_upper':
        return data.hex().upper()
    elif output_format == 'base64':
        return base64.b64encode(data).decode('ascii')
    elif output_format == 'raw':
        return data
    else:
        raise ValueError(f"Format de sortie invalide: {output_format}")

def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement RC4 avec KDF et options similaires au site emn178.github.io",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s "Mon texte" "ma clé"
  %(prog)s "Mon texte" "ma clé" --kdf pbkdf2 --key-size 256
  %(prog)s "Mon texte" "ma clé" --kdf evpkdf --salt-mode random
  %(prog)s "Mon texte" "ma clé" --salt-mode custom --salt "mysalt" --iterations 10000
  %(prog)s "Mon texte" "ma clé" --salt-mode none
  %(prog)s "48656c6c6f" "secret" --input-encoding hex --output-encoding hex_upper --drop 3
  %(prog)s "SGVsbG8gV29ybGQ=" "key" --input-encoding base64 --output-encoding base64
  %(prog)s "75a6" "hi" --decrypt --salt-mode none
        """
    )
    
    parser.add_argument('text', nargs='?', help='Texte à encrypter')
    parser.add_argument('key', nargs='?', help='Clé/passphrase de chiffrement')
    parser.add_argument('--key', dest='key_arg', help='Clé/passphrase de chiffrement')
    
    parser.add_argument('--kdf', choices=['pbkdf2', 'evpkdf', 'none'], 
                       default='pbkdf2', help='Type de dérivation de clé (défaut: pbkdf2)')
    
    parser.add_argument('--key-size', type=int, choices=[40, 56, 64, 80, 128, 192, 256], 
                       default=128, help='Taille de clé en bits (défaut: 128)')
    
    parser.add_argument('--salt-mode', choices=['random', 'custom', 'none'], 
                       default='none', help='Mode du sel: random, custom, none (défaut: none)')
    
    parser.add_argument('--salt', default='', help='Sel personnalisé (utilisé avec --salt-mode custom)')
    
    parser.add_argument('--iterations', type=int, default=1000, 
                       help='Nombre d\'itérations pour PBKDF2 (défaut: 1000)')
    
    parser.add_argument('--input-encoding', choices=['utf8', 'hex', 'base64'], 
                       default='utf8', help='Encodage de l\'entrée')
    
    parser.add_argument('--decrypt', action='store_true', help='Décrypter')
    
    parser.add_argument('--output-encoding', choices=['hex_lower', 'hex_upper', 'base64', 'raw'], 
                       default='hex_lower', help='Encodage de la sortie')
    
    parser.add_argument('--drop', type=int, default=0, help='Octets à supprimer au début')
    
    parser.add_argument('--input-file', help='Fichier d\'entrée')
    parser.add_argument('--output-file', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    key = args.key_arg or args.key
    if not key:
        if args.key is None:
            key = input("Entrez la clé/passphrase de chiffrement: ")
        else:
            key = args.key
    
    final_salt = ''
    
    if args.kdf != 'none':
        derived_key, final_salt = derive_key(
            password=key,
            kdf_type=args.kdf,
            key_size=args.key_size,
            salt=args.salt,
            salt_mode=args.salt_mode,
            iterations=args.iterations
        )
        
        print(f"[Info] KDF: {args.kdf.upper()}, Taille clé: {args.key_size} bits")
        print(f"[Info] Mode sel: {args.salt_mode}")
        if args.salt_mode == 'custom' and args.salt:
            print(f"[Info] Sel personnalisé: {args.salt}")
        if final_salt:
            print(f"[Info] Sel utilisé: {final_salt}")
        if args.kdf == 'pbkdf2':
            print(f"[Info] Itérations: {args.iterations}")
    else:
        derived_key = key.encode() if isinstance(key, str) else key
        print("[Info] Pas de dérivation de clé (mode brut)")
    
    if args.input_file:
        try:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                input_data = f.read()
        except UnicodeDecodeError:
            with open(args.input_file, 'rb') as f:
                input_data = f.read()
                if args.input_encoding == 'utf8':
                    input_data = input_data.hex()
                    args.input_encoding = 'hex'
    elif args.text:
        input_data = args.text
    else:
        if sys.stdin.isatty():
            input_data = input("Entrez le texte à traiter: ")
        else:
            input_data = sys.stdin.read()
    
    rc4 = RC4Cipher(derived_key)
    
    if args.decrypt:
        try:
            if not args.input_encoding == 'hex' and not args.input_encoding == 'base64':
                input_data_clean = input_data.strip().lower()
                is_likely_hex = all(c in '0123456789abcdef' for c in input_data_clean)
                
                if is_likely_hex and len(input_data_clean) % 2 == 0:
                    input_bytes = bytes.fromhex(input_data_clean)
                else:
                    input_bytes = input_data.encode('utf-8')
            else:
                input_bytes = decode_input(input_data, args.input_encoding)
            
            if args.drop > 0:
                if args.drop >= len(input_bytes):
                    raise ValueError(f"Impossible de supprimer {args.drop} octets")
                input_bytes = input_bytes[args.drop:]
            
            result_bytes = rc4.process(input_bytes)
            
            try:
                decoded_result = result_bytes.decode('utf-8')
                if decoded_result.isprintable() or all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded_result):
                    result = decoded_result
                else:
                    result = result_bytes.hex()
                    print("[Info] Résultat déchiffré (hex):")
            except UnicodeDecodeError:
                result = result_bytes.hex()
                print("[Info] Résultat déchiffré (hex):")
        
        except ValueError as e:
            print(f"Erreur: {e}")
            print(f"Données: {input_data[:100]}...")
            sys.exit(1)
            
    else:
        try:
            if args.input_encoding == 'utf8':
                input_bytes = input_data.encode('utf-8')
            else:
                input_bytes = decode_input(input_data, args.input_encoding)
            
            result_bytes = rc4.process(input_bytes)
            result = format_output(result_bytes, args.output_encoding, args.drop)
            
            if final_salt and args.salt_mode == 'random':
                print(f"\n[Important] Conservez ce sel pour le décryptage: {final_salt}")
            
        except ValueError as e:
            print(f"Erreur: {e}")
            sys.exit(1)
    
    if args.output_file:
        try:
            mode = 'w' if isinstance(result, str) else 'wb'
            if mode == 'w':
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    f.write(result)
            else:
                with open(args.output_file, 'wb') as f:
                    f.write(result)
            print(f"Résultat écrit dans {args.output_file}")
        except Exception as e:
            print(f"Erreur: {e}")
            sys.exit(1)
    else:
        print(f"\n{result}")

if __name__ == "__main__":
    main()
