#!/usr/bin/env python3
import base64
import argparse
import sys

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
            raise ValueError(f"Impossible de supprimer {drop_bytes} octets (données de {len(data)} octets)")
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

def is_valid_utf8(data):
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement RC4 avec options similaires au site emn178.github.io",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s "Mon texte" "ma clé"
  %(prog)s "48656c6c6f" "secret" --input-encoding hex --output-encoding hex_upper --drop 3
  %(prog)s "SGVsbG8gV29ybGQ=" "key" --input-encoding base64 --output-encoding base64
  %(prog)s "75a6" "hi" --decrypt
  %(prog)s --input-file input.txt --key "clé" --output-file output.txt --drop 2
        """
    )
    
    parser.add_argument('text', nargs='?', help='Texte à encrypter')
    parser.add_argument('key', nargs='?', help='Clé de chiffrement')
    parser.add_argument('--key', dest='key_arg', help='Clé de chiffrement')
    
    parser.add_argument('--input-encoding', choices=['utf8', 'hex', 'base64'], 
                       default='utf8', help='Encodage de l\'entrée')
    
    parser.add_argument('--decrypt', action='store_true', help='Décrypter')
    
    parser.add_argument('--output-encoding', choices=['hex_lower', 'hex_upper', 'base64', 'raw'], 
                       default='hex_lower', help='Encodage de la sortie')
    
    parser.add_argument('--drop', type=int, default=0, 
                       help='Octets à supprimer au début')
    
    parser.add_argument('--input-file', help='Fichier d\'entrée')
    parser.add_argument('--output-file', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    key = args.key_arg or args.key
    if not key:
        if args.key is None:
            key = input("Entrez la clé de chiffrement: ")
        else:
            key = args.key
    
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
    
    rc4 = RC4Cipher(key)
    
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
        print(result)

if __name__ == "__main__":
    main()
