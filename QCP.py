import sys
import json
import base64
import os
import re
import hashlib
from pgpy import PGPKey, PGPUID, PGPMessage
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
from pgpy.errors import PGPError
from Crypto.PublicKey import ECC
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm

DATABASE_FILE = "keys_database.json"
SIGNED_MESSAGES_FILE = "signed_messages.json"

def initialize_database():
    if not os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, "w") as db:
            json.dump([], db)
    if not os.path.exists(SIGNED_MESSAGES_FILE):
        with open(SIGNED_MESSAGES_FILE, "w") as db:
            json.dump([], db)

def load_keys():
    with open(DATABASE_FILE, "r") as db:
        return json.load(db)

def save_key(key_data):
    keys = load_keys()
    keys.append(key_data)
    with open(DATABASE_FILE, "w") as db:
        json.dump(keys, db)

def list_keys():
    keys = load_keys()
    for index, key in enumerate(keys, start=1):
        key_id = key.get("short_id") or key.get("long_id", "Unknown")
        print(f"{index}. {key['type']} Key - ID: {key_id}")

def get_key_by_index(index):
    keys = load_keys()
    if 0 <= index < len(keys):
        return keys[index]
    else:
        print("Invalid selection.")
        return None

def sign_ecc_message(private_key_pem, message):
    private_key = ECC.import_key(private_key_pem)
    message_hash = int.from_bytes(hashlib.sha256(message.encode('utf-8')).digest(), byteorder='big')
    signature = private_key.sign(message_hash)
    signature_base64 = base64.b64encode(b''.join([signature[0].to_bytes(32, byteorder='big'), signature[1].to_bytes(32, byteorder='big')])).decode('utf-8')
    signed_message = f"-----BEGIN ECC SIGNED MESSAGE-----\n\n{message}\n\n-----ECC SIGNATURE-----\n{signature_base64}\n-----END ECC SIGNATURE-----"
    return signed_message

def generate_ecc_key():
    key = ECC.generate(curve='P-256')
    public_key = key.public_key().export_key(format='PEM')
    private_key = key.export_key(format='PEM')
    key_id = hashlib.sha256(public_key.encode('utf-8')).hexdigest()[:16]
    private_key_base64 = base64.b64encode(private_key.encode('utf-8')).decode('utf-8')
    key_data = {
        "type": "ECC",
        "private_key": private_key_base64,
        "public_key": public_key,
        "short_id": key_id
    }
    save_key(key_data)
    print("\nGenerated ECC Key")
    print(f"Private Key:\n{private_key}")
    print("Public Key:")
    print(public_key)
    print(f"Key ID: {key_id}")
    return private_key_base64, public_key, key_id

def generate_hbs_key():
    private_key = SigningKey.generate()
    public_key = private_key.verify_key.encode(encoder=Base64Encoder)
    key_bytes = public_key.decode('utf-8').encode('utf-8')
    key_id = hashlib.sha256(key_bytes).hexdigest()
    private_key_base64 = base64.b64encode(private_key.encode()).decode()
    key_data = {
        "type": "HBS",
        "private_key": private_key_base64,
        "public_key": public_key.decode(),
        "short_id": key_id
    }
    save_key(key_data)
    print("\nGenerated HBS Key")
    print(f"Private Key:\n{private_key_base64}")
    print(f"Public Key:\n{public_key.decode()}")
    print(f"Key ID: {key_id}")
    return private_key_base64, public_key.decode(), key_id

def generate_pgp_key(name, email, comment="", passphrase="", key_size=2048, hash_algo=HashAlgorithm.SHA256, encryption_prefs={KeyFlags.Sign, KeyFlags.EncryptCommunications}):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, key_size)
    uid = PGPUID.new(name, email, comment)
    key.add_uid(uid, usage=encryption_prefs, hashes=[hash_algo])
    if passphrase:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, hash_algo)
    keyid = key.fingerprint.keyid
    return key, key.pubkey, keyid

def sign_pgp_message(private_key, message, hash_algo=HashAlgorithm.SHA256):
    pgp_message = PGPMessage.new(message)
    signed_message = private_key.sign(pgp_message, hash=hash_algo)
    pgp_signed_message = f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: {hash_algo.name}\n\n{message}\n" + str(signed_message)
    return pgp_signed_message

def sign_hbs_message(private_key, message):
    signed_message = private_key.sign(message.encode("utf-8"))
    return signed_message

def verify_pgp_signature(public_key, signed_message_text):
    try:
        signed_message = PGPMessage.from_blob(signed_message_text)
        verification_result = public_key.verify(signed_message)
        if verification_result:
            print("Signature is valid.")
            for sig in signed_message.signatures:
                keyid = sig.signer
                print(f"gpg: Signature made {sig.created.strftime('%Y-%m-%d %H:%M:%S')} {sig.created.strftime('%Z')}")
                print(f"gpg:                using RSA key {keyid}")
                print("gpg: Good signature from ‘Unknown User’ [full]")  
            return True 
        else:
            print("Signature is invalid.")
            return False
    except PGPError as e:
        print(f"Verification failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during verification: {e}")
    return False

def verify_hbs_signature(public_key, signed_message, original_message):
    try:
        public_key.verify(signed_message, original_message.encode("utf-8"))
        print("\nSignature verified successfully with HBS public key.")
    except Exception as e:
        print(f"\nFailed to verify signature: {e}")

def save_signed_message(message_entry):
    messages = load_signed_messages()
    messages.append(message_entry)
    with open(SIGNED_MESSAGES_FILE, "w") as db:
        json.dump(messages, db)

def load_signed_messages():
    with open(SIGNED_MESSAGES_FILE, "r") as db:
        return json.load(db)

def extract_signature(signed_message_text):
    signature_pattern = r"-----BEGIN PGP SIGNATURE-----\nHash: \w+\n\n(.+?)\n-----END PGP SIGNATURE-----"
    match = re.search(signature_pattern, signed_message_text, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1)
    else:
        print("Could not find the signature part in the signed message.")
        return None

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

    if key_type_choice == "1":
        private_key, public_key, key_id = generate_pgp_key(name, email, comment, passphrase, key_size)
        keys_dir = "keys"
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
        public_key_str = str(public_key)
        public_key_path = os.path.join(keys_dir, f"{key_id}_public.asc")
        with open(public_key_path, "w") as fp:
            fp.write(public_key_str)
        key_data = {
            "type": "PGP",
            "private_key": str(private_key),
            "public_key": str(public_key),
            "public_key_path": public_key_path,
            "long_id": key_id,
            "short_id": key_id[-8:]
        }
        save_key(key_data)
        print(f"Generated PGP Key ID (long): {key_id}")
        print(f"Generated PGP Key ID (short): {key_id[-8:]}")
        print("Generated PGP Private Key:")
        print(private_key)
        print("Generated PGP Public Key:")
        print(public_key)
    elif key_type_choice == "2":
        print("Select Post-Quantum key type:")
        print("1. ECC")
        print("2. HBS")
        pq_key_type_choice = input("Your selection: ")

        if pq_key_type_choice == "1":
            generate_ecc_key()
        elif pq_key_type_choice == "2":
            generate_hbs_key()
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)
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
    if key_data["type"] == "PGP":
        private_key = PGPKey()
        private_key.parse(key_data["private_key"])
        signed_message = sign_pgp_message(private_key, message_text)
        print("\nSigned Message using PGP:")
        print(signed_message)
        save_prompt = input("Would you like to save your message? (y/n): ").lower()
        if save_prompt == "y":
            message_summary = message_text[:20] + "…"
            message_entry = {
                "key_id": key_data["short_id"],
                "summary": message_summary,
                "signed_message": signed_message
            }
            save_signed_message(message_entry)
    elif key_data["type"] == "HBS" or key_data["type"] == "ECC":
        if key_data["type"] == "HBS":
            private_key = SigningKey(key_data["private_key"], encoder=Base64Encoder)
        else:
            private_key = ECC.import_key(base64.b64decode(key_data["private_key"]).decode('utf-8'))
        
        if key_data["type"] == "HBS":
            signed_message = sign_hbs_message(private_key, message_text)
            signed_message_text = f"-----BEGIN HBS SIGNED MESSAGE-----\n\n{message_text}\n\n-----HBS SIGNATURE-----\n{base64.b64encode(signed_message.signature).decode('utf-8')}\n-----END HBS SIGNATURE-----"
        else:
            signed_message_text = sign_ecc_message(private_key, message_text)
        
        print(f"\nSigned Message using {key_data['type']}:")
        print(signed_message_text)
        save_prompt = input("Would you like to save your message? (y/n): ").lower()
        if save_prompt == "y":
            message_summary = message_text[:20] + "…"
            message_entry = {
                "key_id": key_data["short_id"],
                "summary": message_summary,
                "signed_message": signed_message_text
            }
            save_signed_message(message_entry)
    else:
        print("Invalid key type.")

def verify_message():
    print("Select a key to use for verification:")
    list_keys()
    key_index = int(input("Your selection: ")) - 1
    key_data = get_key_by_index(key_index)

    if not key_data:
        print("Invalid key selection.")
        return

    try:
        with open(SIGNED_MESSAGES_FILE, "r") as file:
            messages = json.load(file)
    except FileNotFoundError:
        print("No saved messages found.")
        return

    if messages:
        print("\nSaved Signed Messages:")
        for index, message in enumerate(messages, start=1):
            print(f"{index}. ID: {message['key_id']} Message: {message['summary']}")

        message_selection = int(input("Select a message to verify (enter its number), or enter 0 to manually input a message: "))
        if message_selection > 0 and message_selection <= len(messages):
            signed_message_text = messages[message_selection - 1]["signed_message"]
        else:
            signed_message_text = input("Enter the full signed message: ")

        if key_data["type"] == "PGP":
            if "public_key" not in key_data:
                print("Public key not found.")
                return
            public_key = PGPKey()
            public_key.parse(key_data["public_key"])
            return verify_pgp_signature(public_key, signed_message_text)
        elif key_data["type"] in ("HBS", "ECC"):
            if "public_key" not in key_data:
                print("Public key not found.")
                return
            public_key = VerifyKey(key_data["public_key"], encoder=Base64Encoder)
            original_message, signed_signature = extract_hbs_parts(signed_message_text)
            if not original_message or not signed_signature:
                print("Failed to extract original message and signature.")
                return
            verify_hbs_signature(public_key, signed_signature, original_message)
        else:
            print("Unsupported key type for this operation.")

def extract_hbs_parts(signed_message):
    pattern = r"-----BEGIN HBS SIGNED MESSAGE-----\n\n(.+?)\n\n-----HBS SIGNATURE-----\n(.+?)\n-----END HBS SIGNATURE-----"
    match = re.search(pattern, signed_message, re.DOTALL)
    if match:
        original_message = match.group(1)
        signed_signature = base64.b64decode(match.group(2))
        return original_message, signed_signature
    print("Failed to extract parts from HBS signed message.")
    return None, None

def clear_all_data():
    with open(DATABASE_FILE, "w") as db:
        json.dump([], db)
    print("All keys have been cleared.")

    with open(SIGNED_MESSAGES_FILE, "w") as file:
        json.dump([], file)
    print("All signed messages have been cleared.")

def main():
    initialize_database()
    while True:
        print("\nMenu:")
        print("1. Create a new PGP or Post-Quantum key")
        print("2. Verify a signed message")
        print("3. Sign a new message")
        print("4. Clear all keys and messages")
        print("5. Exit")
        choice = input("Your selection: ")
        if choice == "1":
            create_new_key()
        elif choice == "2":
            verify_message()
        elif choice == "3":
            sign_message()
        elif choice == "4":
            clear_all_data()
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
