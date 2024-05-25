import sys
import json
import hashlib
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
from pgpy.errors import PGPError
from Crypto.PublicKey import ECC
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
import base64
import os
import re

DATABASE_FILE = 'keys_database.json'
SIGNED_MESSAGES_FILE = 'signed_messages.txt'

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

def extract_signature(signed_message_text):
    # Define the pattern to match the entire signature block, including possible leading/trailing whitespace/newlines
    signature_pattern = r'(?:\s*-----BEGIN PGP SIGNATURE-----[\s\S]*?\s*-----END PGP SIGNATURE-----\s*)'
    
    # Search for the signature block in the signed message text
    match = re.search(signature_pattern, signed_message_text, re.MULTILINE | re.DOTALL)
    
    if match:
        # Return the matched signature block
        return match.group(0)
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

    if key_type_choice == '1':
        private_key, public_key, key_id = generate_pgp_key(name, email, comment, passphrase, key_size)
        # Check if the 'keys' directory exists, if not, create it
        keys_dir = 'keys'
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)

        # Serialize the public key to a string and write it to a file
        public_key_str = str(public_key)
        public_key_path = os.path.join(keys_dir, f'{key_id}_public.asc')
        with open(public_key_path, 'w') as fp:
            fp.write(public_key_str)
        key_data = {
            'type': 'PGP',
            'private_key': str(private_key),
            'public_key_path': public_key_path,  # Include the public key path
            'long_id': key_id,
            'short_id': key_id[-8:]
        }
        save_key(key_data)
        print(f"Generated PGP Key ID (long): {key_id}")
        print(f"Generated PGP Key ID (short): {key_id[-8:]}")
        print("Generated PGP Private Key:")
        print(private_key)
        print("Generated PGP Public Key:")
        print(open(public_key_path).read())
    elif key_type_choice == '2':
        # Similar logic for Post-Quantum keys, adjusting for different key types and saving mechanisms
        pass
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
        save_prompt = input("Would you like to save your message? (y/n): ").lower()
        if save_prompt == 'y':
            message_summary = message_text[:20] + "..."  # Use the first 20 characters as a summary
            message_entry = {
                "key_id": key_data['short_id'],
                "summary": message_summary,
                "signed_message": signed_message
            }
            with open(SIGNED_MESSAGES_FILE, 'a') as file:
                file.write(json.dumps(message_entry) + "\n")
    elif key_data['type'] in ['HBS', 'ECC']:
        private_key = SigningKey(key_data['private_key'], encoder=Base64Encoder)
        signed_message = sign_hbs_message(private_key, message_text)
        signed_message_base64 = base64.b64encode(signed_message.signature).decode('utf-8')
        custom_signed_message = f"-----BEGIN HBS SIGNED MESSAGE-----\n\n{message_text}\n\n-----BEGIN HBS SIGNATURE-----\n{signed_message_base64}\n-----END HBS SIGNATURE-----"
        print("\nSigned Message using HBS:")
        print(custom_signed_message)
        save_prompt = input("Would you like to save your message? (y/n): ").lower()
        if save_prompt == 'y':
            message_summary = message_text[:20] + "..."  # Use the first 20 characters as a summary
            message_entry = {
                "key_id": key_data['short_id'],
                "summary": message_summary,
                "signed_message": custom_signed_message
            }
            with open(SIGNED_MESSAGES_FILE, 'a') as file:
                file.write(json.dumps(message_entry) + "\n")

def verify_message():
    print("Select a key to use for verification:")
    list_keys()
    key_index = int(input("Your selection: ")) - 1
    key_data = get_key_by_index(key_index)

    if not key_data:
        return

    # Attempt to load and display structured message entries
    try:
        with open(SIGNED_MESSAGES_FILE, 'r') as file:
            messages = [json.loads(line) for line in file]
    except FileNotFoundError:
        messages = []

    if messages:
        print("\nSaved Signed Messages:")
        for index, message in enumerate(messages, start=1):
            print(f"{index}. ID: {message['key_id']} Message: {message['summary']}")
        
        message_selection = int(input("Select a message to verify (enter its number), or enter 0 to manually input a message: "))
        if message_selection > 0 and message_selection <= len(messages):
            signed_message_text = messages[message_selection - 1]['signed_message']
        else:
            signed_message_text = input("Enter the signed message: ")

        # Extract the signature part from the signed message
        signature_part = extract_signature(signed_message_text)

        if signature_part is None:
            print("Could not find the signature part in the signed message.")
            return

        # Proceed with verification
        if key_data['type'] == 'PGP':
            try:
                public_key = PGPKey.from_file(key_data['public_key_path'])[0]
                # Convert the signature part to bytes if necessary
                signature_bytes = signature_part.encode('utf-8')
                verify_result = public_key.verify(signature_bytes)
                if verify_result:
                    print("Verification successful.")
                else:
                    print("Signature is invalid.")
            except PGPError as e:
                print(f"An error occurred during verification: {e}")
        elif key_data['type'] == 'HBS':
            # Similar approach for HBS, assuming you have the necessary imports and setup
            pass
        elif key_data['type'] == 'ECC':
            print("ECC signature verification is not implemented yet.")
        else:
            print("Invalid key type.")
    else:
        print("No saved messages found.")


def clear_all_data():
    # Clear keys database
    with open(DATABASE_FILE, 'w') as db:
        json.dump([], db)
    print("All keys have been cleared.")

    # Clear signed messages file
    with open(SIGNED_MESSAGES_FILE, 'w') as file:
        pass  # Writing nothing to the file effectively clears it
    print("All signed messages have been cleared.")



# Update the main function to include the new menu options
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
        if choice == '1':
            create_new_key()
        elif choice == '2':
            verify_message()
        elif choice == '3':
            sign_message()
        elif choice == '4':
            clear_all_data()
        elif choice == '5':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
