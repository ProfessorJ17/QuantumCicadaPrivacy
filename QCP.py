import sys
import json
import hashlib
from pgpy import PGPKey, PGPUID, PGPMessage
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
from Crypto.PublicKey import ECC
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
import base64
import os

DATABASE_FILE = 'keys_database.json'

def initialize_database():
    if not os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, 'w') as db:
            json.dump([], db)

def load_keys():
    with open(DATABASE_FILE, 'r') as db:
        return json.load(db)

def save_key(key_data):
    keys = load_keys()
    keys.append(key_data)
    with open(DATABASE_FILE, 'w') as db:
        json.dump(keys, db)

def list_keys():
    keys = load_keys()
    for index, key in enumerate(keys, start=1):
        print(f"{index}. {key['type']} Key - ID: {key['short_id']}")

def get_key_by_index(index):
    keys = load_keys()
    if 0 <= index < len(keys):
        return keys[index]
    else:
        print("Invalid selection.")
        return None

def generate_ecc_key():
    key = ECC.generate(curve='P-256')
    public_key = key.public_key()
    return key, public_key

def generate_pgp_key(name, email, comment='', passphrase='', key_size=2048, hash_algo=HashAlgorithm.SHA256, encryption_prefs={KeyFlags.Sign, KeyFlags.EncryptCommunications}):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, key_size)
    uid = PGPUID.new(name, email, comment)
    key.add_uid(uid, usage=encryption_prefs, hashes=[hash_algo])
    if passphrase:
        key.protect(passphrase, hash_algo)
    keyid = key.fingerprint.keyid
    return key, key.pubkey, keyid

def generate_hbs_key():
    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    return private_key, public_key

def sign_pgp_message(private_key, message, hash_algo=HashAlgorithm.SHA256):
    signed_message = private_key.sign(message, hash_algo=hash_algo)
    pgp_signed_message = f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: {hash_algo.name}\n\n{message}\n\n{str(signed_message)}"
    return pgp_signed_message

def sign_hbs_message(private_key, message):
    signed_message = private_key.sign(message.encode('utf-8'))
    return signed_message

def verify_pgp_signature(public_key, signed_message):
    try:
        verified = public_key.verify(signed_message)
        if verified:
            keyid = signed_message.signatures[0].signer
            creation_time = signed_message.signatures[0].creation_time
            signee = signed_message.signatures[0].signee
            print(f"gpg: Signature made {creation_time.strftime('%Y-%m-%d %H:%M:%S')} {creation_time.strftime('%Z')}")
            print(f"gpg:                using RSA key {keyid}")
            print(f"gpg: Good signature from '{signee}' [full]")
            return True
        else:
            print("Signature is invalid.")
            return False
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def verify_hbs_signature(public_key, signed_message, original_message):
    try:
        signed_message_bytes = base64.b64decode(signed_message)
        if len(signed_message_bytes) != 64:
            raise ValueError("The signature must be exactly 64 bytes long")
        public_key.verify(signed_message_bytes, original_message.encode('utf-8'))
        print("\nSignature verified successfully with HBS public key.")
    except Exception as e:
        print(f"\nFailed to verify signature: {e}")

def create_new_key():
    print("Select key type:")
    print("1. RSA (Traditional PGP)")
    print("2. Post-Quantum")
    key_type_choice = input("Your selection: ")

    name = input("Enter your name: ")
    email = input("Enter your email: ")
    comment = input("Enter optional comment (press Enter to skip): ")
    passphrase = input("Enter passphrase for your key (press Enter to skip): ")
    key_size = int(input("Enter key size (default: 2048, recommended: 4096): ") or "2048")

    if key_type_choice == '1':
        private_key, public_key, key_id = generate_pgp_key(name, email, comment, passphrase, key_size)
        key_data = {
            'type': 'PGP',
            'private_key': str(private_key),
            'public_key': str(public_key),
            'long_id': key_id,
            'short_id': key_id[-8:]
        }
        save_key(key_data)
        print(f"Generated PGP Key ID (long): {key_id}")
        print(f"Generated PGP Key ID (short): {key_id[-8:]}")
        print("Generated PGP Private Key:")
        print(private_key)
        print("Generated PGP Public Key:")
        print(public_key)
    elif key_type_choice == '2':
        print("Select post-quantum algorithm:")
        print("1. ECC (Elliptic Curve Cryptography)")
        print("2. HBS (Hash-Based Signatures)")
        pq_algorithm_choice = input("Your selection: ")

        if pq_algorithm_choice == '1':
            private_key, public_key = generate_ecc_key()
        elif pq_algorithm_choice == '2':
            private_key, public_key = generate_hbs_key()
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)

        public_key_encoded = public_key.encode(Base64Encoder).decode('utf-8')
        key_id_long = hashlib.sha256(public_key.encode()).hexdigest()
        key_id_short = key_id_long[-8:]
        key_data = {
            'type': 'HBS' if pq_algorithm_choice == '2' else 'ECC',
            'private_key': private_key.encode(Base64Encoder).decode('utf-8'),
            'public_key': public_key_encoded,
            'long_id': key_id_long,
            'short_id': key_id_short
        }
        save_key(key_data)

        print("\nGenerated Post-Quantum Keys:")
        print("Private Key:")
        print(private_key.encode(Base64Encoder).decode('utf-8'))
        print("Public Key:")
        print(public_key_encoded)
        print("\nGenerated Post-Quantum Key ID (long):")
        print(key_id_long)
        print("Generated Post-Quantum Key ID (short):")
        print(key_id_short)
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

def sign_message():
    print("Select a key to use for signing:")
    list_keys()
    key_index = int(input("Your selection: ")) - 1
    key_data = get_key_by_index(key_index)

    if not key_data:
        return

    message_text = input("Enter your message to sign: ")
    if key_data['type'] == 'PGP':
        private_key = PGPKey()
        private_key.parse(key_data['private_key'])
        signed_message = sign_pgp_message(private_key, message_text)
        print("\nSigned Message using PGP:")
        print(signed_message)
    elif key_data['type'] in ['HBS', 'ECC']:
        private_key = SigningKey(key_data['private_key'], encoder=Base64Encoder)
        signed_message = sign_hbs_message(private_key, message_text)
        signed_message_base64 = base64.b64encode(signed_message.signature).decode('utf-8')
        custom_signed_message = f"-----BEGIN HBS SIGNED MESSAGE-----\n\n{message_text}\n\n-----BEGIN HBS SIGNATURE-----\n{signed_message_base64}\n-----END HBS SIGNATURE-----"
        print("\nSigned Message using HBS:")
        print(custom_signed_message)

def verify_message():
    print("Select a key to use for verification:")
    list_keys()
    key_index = int(input("Your selection: ")) - 1
    key_data = get_key_by_index(key_index)

    if not key_data:
        return

    signed_message_text = input("Enter the signed message: ")
    message_text = input("Enter the original message: ")

    if key_data['type'] == 'PGP':
        public_key = PGPKey()
        public_key.parse(key_data['public_key'])
        signed_message = PGPMessage()
        signed_message.parse(signed_message_text)
        verify_pgp_signature(public_key, signed_message)
    elif key_data['type'] == 'HBS':
        public_key = VerifyKey(key_data['public_key'], encoder=Base64Encoder)
        verify_hbs_signature(public_key, signed_message_text, message_text)
    elif key_data['type'] == 'ECC':
        print("ECC signature verification is not implemented yet.")
    else:
        print("Invalid key type.")

def main():
    initialize_database()
    while True:
        print("\nMenu:")
        print("1. Create a new PGP or Post-Quantum key")
        print("2. Verify a signed message")
        print("3. Sign a new message")
        print("4. Exit")
        choice = input("Your selection: ")
        if choice == '1':
            create_new_key()
        elif choice == '2':
            verify_message()
        elif choice == '3':
            sign_message()
        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
