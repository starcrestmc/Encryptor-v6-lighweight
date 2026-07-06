# Original Module built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6/tree/main/EXTRAMODULES

import warnings
warnings.filterwarnings("ignore") # Suppress all warnings
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from datetime import timedelta
import os

def POST(): # Test for keys and make them if they dont exist (POST = Power on Self Test)
    key_dir = "PGPKeys"
    os.makedirs(key_dir, exist_ok=True) # Make the folder if it doesnt already exist

    public_key_path = os.path.join(key_dir, "public.asc")
    private_key_path = os.path.join(key_dir, "private.asc")

    pubkey = os.path.isfile(public_key_path)
    privkey = os.path.isfile(private_key_path)

    if not pubkey or not privkey:
        # Delete whichever key exists, so both can be freshly created
        if pubkey:
            os.remove(public_key_path)
        elif privkey:
            os.remove(private_key_path)

        # Create the key
            
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

        # Anonymous Keypair Details
        uid = pgpy.PGPUID.new("John Smith", email="empty@email.com")

        # Add UID to key with preferences
        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            key_expires=timedelta(days=3650)
        )
        
# Original Module built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6/tree/main/EXTRAMODULES
        
        # Export ASCII-armored versions
        with open(private_key_path, "w") as f:
            f.write(str(key))

        with open(public_key_path, "w") as f:
            f.write(str(key.pubkey))

        fp = key.fingerprint
        formatted = ' '.join(fp[i:i+4] for i in range(0, len(fp), 4))
        print("\n\nYour PGP Fingerprint is: ", formatted)
        print("[This message will only show once, Note this down incase you need to verify with a friend]\n")

def enc(loc1,loc2,msg):
    load_key = lambda name: pgpy.PGPKey.from_file(name)[0]
    sk = load_key(loc1)
    rk = load_key(loc2)
    message = pgpy.PGPMessage.new(msg)
    with sk.unlock(None):
        # Sign the message
        message |= sk.sign(message)

    encrypted_message = rk.encrypt(message)
    return str(encrypted_message)


def dec(loc1,loc2,ciphertext):
    load_key = lambda name: pgpy.PGPKey.from_file(name)[0]
    sk = load_key(loc1)
    vk = load_key(loc2)
    enc_msg = pgpy.PGPMessage.from_blob(ciphertext)
    with sk.unlock(None):
        dec_msg = sk.decrypt(enc_msg)

    verified = vk.verify(dec_msg)
    
    return dec_msg,verified

# Original Module built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6/tree/main/EXTRAMODULES
