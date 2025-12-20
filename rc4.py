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

def pbkdf2(password, salt, key_size, hash_algo='sha1', iterations=1000):
    password = password.encode() if isinstance(password, str) else password
    salt = salt.encode() if isinstance(salt, str) else salt
    
    hash_func = getattr(hashlib, hash_algo, hashlib.sha1)
    key = b''
    block_index = 1
    
    while len(key) < key_size:
        u = hmac.new(password, salt + struct.pack('>I', block_index), hash_func).digest()
        result = u
        
        for _ in range(1, iterations):
            u = hmac.new(password, u, hash_func).digest()
            result = bytes(a ^ b for a, b in zip(result, u))
        
        key += result
        block_index += 1
    
    return key[:key_size]

def evpkdf(password, salt, key_size, hash_algo='md5', iterations=1):
    password = password.encode() if isinstance(password, str) else password
    salt = salt.encode() if isinstance(salt, str) else salt
    
    hash_func = getattr(hashlib, hash_algo, hashlib.md5)
    key = b''
    
    while len(key) < key_size:
        data = password + salt if len(key) == 0 else key[-len(salt):] if len(salt) > 0 else key
        for _ in range(iterations):
            hash_obj = hash_func()
            hash_obj.update(data)
            data = hash_obj.digest()
        key += data
    
    return key[:key_size]

def simple_hash(password, hash_algo='sha256'):
    password = password.encode() if isinstance(password, str) else password
    hash_func = getattr(hashlib, hash_algo, hashlib.sha256)
    
    return hash_func(password).digest()

def ripemd160_hash(password):
    import hashlib
    try:
        ripemd160 = hashlib.new('ripemd160')
    except ValueError:
        print("[Erreur] RIPEMD-160 n'est pas disponible sur votre système")
        print("[Info] Utilisation de SHA256 comme fallback")
        return hashlib.sha256(password.encode() if isinstance(password, str) else password).digest()
    
    ripemd160.update(password.encode() if isinstance(password, str) else password)
    return ripemd160.digest()

def generate_random_salt(length=16):
    return secrets.token_hex(length)

def derive_key(password, key_type='pbkdf2', key_size=128, salt='', salt_mode='none', 
               hash_algo='sha1', iterations=1000):
    key_size_bytes = key_size // 8
    
    if salt_mode == 'random':
        salt = generate_random_salt()
        print(f"[Info] Sel généré aléatoirement: {salt}")
    elif salt_mode == 'none':
        salt = ''
    elif salt_mode == 'custom':
        salt = salt
    
    if key_type == 'pbkdf2':
        return pbkdf2(password, salt, key_size_bytes, hash_algo, iterations), salt
    elif key_type == 'evpkdf':
        return evpkdf(password, salt, key_size_bytes, hash_algo, iterations), salt
    elif key_type == 'hash':
        if hash_algo == 'ripemd160':
            hashed_key = ripemd160_hash(password)
        else:
            hashed_key = simple_hash(password, hash_algo)
        
        if len(hashed_key) < key_size_bytes:
            while len(hashed_key) < key_size_bytes:
                hashed_key += hashlib.sha256(hashed_key).digest()
        return hashed_key[:key_size_bytes], salt
    elif key_type == 'none':
        raw_key = password.encode() if isinstance(password, str) else password
        if len(raw_key) < key_size_bytes:
            raw_key = raw_key.ljust(key_size_bytes, b'\0')
        return raw_key[:key_size_bytes], salt
    else:
        raise ValueError(f"Type de clé inconnu: {key_type}")

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
        description="Chiffrement RC4 avec support KDF et hash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Hash simple
  %(prog)s "Mon texte" "ma clé" --key-type hash --hash-algo sha256
  
  # PBKDF2 avec SHA512
  %(prog)s "Secret" "pass" --key-type pbkdf2 --hash-algo sha512 --salt-mode random
  
  # EvpKDF avec MD5 (comportement original)
  %(prog)s "Data" "key" --key-type evpkdf --hash-algo md5
  
  # RIPEMD-160 hash
  %(prog)s "Texte" "password" --key-type hash --hash-algo ripemd160
  
  # Clé brute sans transformation
  %(prog)s "Hello" "rawkey123" --key-type none
        """
    )
    
    parser.add_argument('text', nargs='?', help='Texte à encrypter')
    parser.add_argument('key', nargs='?', help='Clé/passphrase de chiffrement')
    parser.add_argument('--key', dest='key_arg', help='Clé/passphrase de chiffrement')
    
    parser.add_argument('--key-type', choices=['pbkdf2', 'evpkdf', 'hash', 'none'], 
                       default='pbkdf2', help='Type de génération de clé')
    
    parser.add_argument('--hash-algo', choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160'], 
                       default='sha1', help='Algorithme de hash (défaut: sha1)')
    
    parser.add_argument('--key-size', type=int, choices=[40, 56, 64, 80, 128, 192, 256], 
                       default=128, help='Taille de clé en bits')
    
    parser.add_argument('--salt-mode', choices=['random', 'custom', 'none'], 
                       default='none', help='Mode du sel')
    
    parser.add_argument('--salt', default='', help='Sel personnalisé')
    
    parser.add_argument('--iterations', type=int, default=1000, 
                       help='Nombre d\'itérations pour PBKDF2')
    
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
    
    try:
        derived_key, final_salt = derive_key(
            password=key,
            key_type=args.key_type,
            key_size=args.key_size,
            salt=args.salt,
            salt_mode=args.salt_mode,
            hash_algo=args.hash_algo,
            iterations=args.iterations
        )
        
        print(f"[Info] Type clé: {args.key_type.upper()}, Hash: {args.hash_algo.upper()}")
        print(f"[Info] Taille clé: {args.key_size} bits")
        print(f"[Info] Mode sel: {args.salt_mode}")
        if args.salt_mode == 'custom' and args.salt:
            print(f"[Info] Sel personnalisé: {args.salt}")
        if final_salt:
            print(f"[Info] Sel utilisé: {final_salt}")
        if args.key_type == 'pbkdf2':
            print(f"[Info] Itérations: {args.iterations}")
    except Exception as e:
        print(f"[Erreur] Échec de la dérivation de clé: {e}")
        sys.exit(1)
    
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
