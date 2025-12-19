import base64
import argparse
import sys

class RC4Cipher:
    def __init__(self, key):
        # ===================== INITIALISE CHIFFREMENT RC4 =====================
        self.key = key.encode() if isinstance(key, str) else key
        
        # Initialisation S-box
        self.S = list(range(256))
        j = 0
        key_length = len(self.key)
        
        # Key Scheduling Algorithm (KSA)
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def process(self, data):
        # ===================== TRAITEMENT DES DATAS =====================
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Pseudo-Random Generation Algorithm (PRGA)
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

def format_output(data, output_format):
    # ===================== OUTPUT FORMATING =====================
    if output_format == 'hex':
        return data.hex()
    elif output_format == 'base64':
        return base64.b64encode(data).decode('ascii')
    elif output_format == 'utf8':
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return f"[Données binaires - utiliser hex ou base64 pour affichage]\nHex: {data.hex()}"
    elif output_format == 'binary':
        return ' '.join(f'{byte:08b}' for byte in data)
    else:
        raise ValueError(f"Format invalide: {output_format}")

def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement RC4 avec options supplémentaires perméttant un bon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s "Mon texte" "ma clé" --format hex
  %(prog)s "Hello" "secret" --format base64
  echo -n "Texte" | %(prog)s --key "ma clé" --format hex
  %(prog)s --decrypt --input-file encrypted.txt --key "clé" --output-file decrypted.txt
        """
    )
    
    # Arguments
    parser.add_argument('text', nargs='?', help='Texte à encrypter (si non spécifié, lecture depuis stdin)')
    parser.add_argument('key', nargs='?', help='Clé de chiffrement')
    parser.add_argument('--key', dest='key_arg', help='Clé de chiffrement (alternative)')
    parser.add_argument('--decrypt', action='store_true', help='Décrypter au lieu d\'encrypter')
    parser.add_argument('--format', choices=['hex', 'base64', 'utf8', 'binary'], 
                       default='hex', help='Format de sortie (défaut: hex)')
    parser.add_argument('--input-file', help='Fichier d\'entrée')
    parser.add_argument('--output-file', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    # Déterminer la clé
    key = args.key_arg or args.key
    if not key:
        if args.key is None:
            key = input("Entrez la clé de chiffrement: ")
        else:
            key = args.key
    
    # Lire l'entrée
    if args.input_file:
        with open(args.input_file, 'rb') as f:
            input_data = f.read()
        if isinstance(input_data, bytes):
            input_data = input_data.decode('utf-8', errors='ignore')
    elif args.text:
        input_data = args.text
    else:
        # Lecture depuis stdin
        if sys.stdin.isatty():
            input_data = input("Entrez le texte à traiter: ")
        else:
            input_data = sys.stdin.read()
    
    # Traitement
    rc4 = RC4Cipher(key)
    
    if args.decrypt:
        # Pour le décryptage, nous devons d'abord décoder selon le format
        if args.format == 'hex':
            input_bytes = bytes.fromhex(input_data.strip())
        elif args.format == 'base64':
            input_bytes = base64.b64decode(input_data.strip())
        elif args.format == 'binary':
            # Supprimer les espaces et convertir binaire en bytes
            binary_str = input_data.replace(' ', '').strip()
            input_bytes = bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))
        else:  # utf8
            input_bytes = input_data.encode('utf-8')
        
        result_bytes = rc4.process(input_bytes)
        result = result_bytes.decode('utf-8', errors='replace')
    else:
        # Cryptage
        result_bytes = rc4.process(input_data)
        result = format_output(result_bytes, args.format)
    
    # Sortie
    if args.output_file:
        mode = 'w' if isinstance(result, str) else 'wb'
        if mode == 'w':
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(result)
        else:
            with open(args.output_file, 'wb') as f:
                f.write(result)
        print(f"Résultat écrit dans {args.output_file}")
    else:
        print(result)

if __name__ == "__main__":
    main()
