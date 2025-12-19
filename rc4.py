#!/usr/bin/env python3
import base64
import argparse
import sys

class RC4Cipher:
    def __init__(self, key):
        # === INITIALISE CHIFFREMENT RC4 ===
        self.key = key.encode() if isinstance(key, str) else key
        
        # === INITIALISATION S-BOX ===
        self.S = list(range(256))
        j = 0
        key_length = len(self.key)
        
        # === KEY SCHEDULING ALGORITHM (KSA) ===
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def process(self, data):
        # === TRAITEMENT DES DONNEES ===
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # === PSEUDO-RANDOM GENERATION ALGORITHM (PRGA) ===
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
    # === DECODE L'ENTREE SELON LE FORMAT SPECIFIE ===
    data = data.strip()
    
    if input_encoding == 'utf8':
        return data.encode('utf-8')
    elif input_encoding == 'hex':
        # === NETTOYAGE ENTREE HEXADECIMALE ===
        data = ''.join(c for c in data if c.isalnum())
        return bytes.fromhex(data)
    elif input_encoding == 'base64':
        # === NETTOYAGE ENTREE BASE64 ===
        data = ''.join(c for c in data if c.isalnum() or c in '+/=')
        return base64.b64decode(data)
    else:
        raise ValueError(f"Encodage d'entrée invalide: {input_encoding}")

def format_output(data, output_format, drop_bytes=0):
    # === FORMATAGE SORTIE ET SUPPRESSION OCTETS ===
    # === APPLIQUER SUPPRESSION OCTETS ===
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
    # === VERIFIE SI LES DONNEES SONT VALIDES EN UTF-8 ===
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def main():
    # === CONFIGURATION ARGUMENTS ===
    parser = argparse.ArgumentParser(
        description="Chiffrement RC4 avec options similaires au site emn178.github.io",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Encryptage UTF-8 vers hex minuscule
  %(prog)s "Mon texte" "ma clé"
  
  # Encryptage hex vers hex majuscule avec suppression de 3 octets
  %(prog)s "48656c6c6f" "secret" --input-encoding hex --output-encoding hex_upper --drop 3
  
  # Encryptage base64 vers base64
  %(prog)s "SGVsbG8gV29ybGQ=" "key" --input-encoding base64 --output-encoding base64
  
  # Décryptage hex vers UTF-8
  %(prog)s "75a6" "hi" --decrypt
  
  # Avec fichiers
  %(prog)s --input-file input.txt --key "clé" --output-file output.txt --drop 2
        """
    )
    
    # === ARGUMENTS PRINCIPAUX ===
    parser.add_argument('text', nargs='?', help='Texte à encrypter (si non spécifié, lecture depuis stdin)')
    parser.add_argument('key', nargs='?', help='Clé de chiffrement')
    parser.add_argument('--key', dest='key_arg', help='Clé de chiffrement (alternative)')
    
    # === OPTIONS ENCODAGE ENTREE ===
    parser.add_argument('--input-encoding', choices=['utf8', 'hex', 'base64'], 
                       default='utf8', help='Encodage de l\'entrée (défaut: utf8)')
    
    # === OPTIONS DECRYPTAGE ===
    parser.add_argument('--decrypt', action='store_true', help='Décrypter au lieu d\'encrypter')
    
    # === OPTIONS ENCODAGE SORTIE ===
    parser.add_argument('--output-encoding', choices=['hex_lower', 'hex_upper', 'base64', 'raw'], 
                       default='hex_lower', help='Encodage de la sortie (défaut: hex_lower)')
    
    # === OPTION DROP (BYTES) ===
    parser.add_argument('--drop', type=int, default=0, 
                       help='Nombre d\'octets à supprimer au début du résultat (défaut: 0)')
    
    # === OPTIONS FICHIERS ===
    parser.add_argument('--input-file', help='Fichier d\'entrée')
    parser.add_argument('--output-file', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    # === GESTION DE LA CLÉ ===
    key = args.key_arg or args.key
    if not key:
        if args.key is None:
            key = input("Entrez la clé de chiffrement: ")
        else:
            key = args.key
    
    # === LECTURE DE L'ENTREE ===
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
        # === LECTURE DEPUIS STDIN ===
        if sys.stdin.isatty():
            input_data = input("Entrez le texte à traiter: ")
        else:
            input_data = sys.stdin.read()
    
    # === TRAITEMENT PRINCIPAL ===
    rc4 = RC4Cipher(key)
    
    if args.decrypt:
        # === DECRYPTAGE ===
        try:
            # IMPORTANT: Pour le décryptage, on utilise toujours hex comme encodage d'entrée
            # sauf si l'utilisateur spécifie explicitement un autre encodage
            if not args.input_encoding == 'hex' and not args.input_encoding == 'base64':
                # Si l'utilisateur n'a pas spécifié d'encodage, on essaie de deviner
                input_data_clean = input_data.strip().lower()
                # Vérifier si ça ressemble à de l'hex (seulement 0-9a-f)
                is_likely_hex = all(c in '0123456789abcdef' for c in input_data_clean)
                
                if is_likely_hex and len(input_data_clean) % 2 == 0:
                    # C'est probablement de l'hex, même si l'utilisateur n'a pas spécifié --input-encoding hex
                    input_bytes = bytes.fromhex(input_data_clean)
                else:
                    # Sinon, on utilise l'encodage par défaut (utf8)
                    input_bytes = input_data.encode('utf-8')
            else:
                # L'utilisateur a spécifié un encodage, on l'utilise
                input_bytes = decode_input(input_data, args.input_encoding)
            
            # === SUPPRESSION OCTETS POUR DECRYPTAGE ===
            if args.drop > 0:
                if args.drop >= len(input_bytes):
                    raise ValueError(f"Impossible de supprimer {args.drop} octets (données de {len(input_bytes)} octets)")
                input_bytes = input_bytes[args.drop:]
            
            # === DECRYPTAGE RC4 ===
            result_bytes = rc4.process(input_bytes)
            
            # === AFFICHAGE RESULTAT ===
            # Essayer d'afficher en UTF-8 d'abord
            try:
                decoded_result = result_bytes.decode('utf-8')
                # Vérifier si c'est du texte affichable
                if decoded_result.isprintable() or all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded_result):
                    result = decoded_result
                else:
                    result = result_bytes.hex()
                    print("[Info] Résultat déchiffré (hex):")
            except UnicodeDecodeError:
                result = result_bytes.hex()
                print("[Info] Résultat déchiffré (hex):")
        
        except ValueError as e:
            print(f"Erreur lors du décodage de l'entrée: {e}")
            print(f"Données d'entrée: {input_data[:100]}...")
            sys.exit(1)
            
    else:
        # === ENCRYPTAGE ===
        try:
            # === DECODAGE ENTREE ===
            if args.input_encoding == 'utf8':
                input_bytes = input_data.encode('utf-8')
            else:
                input_bytes = decode_input(input_data, args.input_encoding)
            
            # === ENCRYPTAGE RC4 ===
            result_bytes = rc4.process(input_bytes)
            
            # === FORMATAGE SORTIE ===
            result = format_output(result_bytes, args.output_encoding, args.drop)
            
        except ValueError as e:
            print(f"Erreur lors du traitement: {e}")
            if args.input_encoding == 'hex':
                print("Vérifiez que l'entrée hexadécimale est valide (longueur paire, caractères 0-9a-fA-F)")
            elif args.input_encoding == 'base64':
                print("Vérifiez que l'entrée base64 est valide")
            sys.exit(1)
    
    # === ECRITURE DE LA SORTIE ===
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
            print(f"Erreur lors de l'écriture dans {args.output_file}: {e}")
            sys.exit(1)
    else:
        print(result)

if __name__ == "__main__":
    main()
