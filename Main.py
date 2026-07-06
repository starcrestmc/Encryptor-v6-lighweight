# Original tool built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6
from secrets import randbelow as rb
from secrets import choice as ch
import time as t
import os
try:
    import imghdr
    import secrets
    import json
    import base64
    import string
    from hashlib import sha256
    import getpass
    import pgpy
    import shutil
    import pickle as pk
except:
    reqirements_install = input("Would you like to install the Requirements? [Y]es/[N]o: ")
    if reqirements_install.lower() == "y":
        os.system('cmd /c "color a & echo [Python]: Installing Requirements & @echo off & pip install -r requirements.txt & timeout /t 3 /nobreak"')
    else:
        print("This script wont run without pgpy, hashlib, nltk and cryptography")
        print("Please install manually if you want to use this")
        t.sleep(3)
        exit()

from EXTRAMODULES import PGPmsg
from EXTRAMODULES import pre

import nltk
from nltk.corpus import brown
from nltk import pos_tag
nltk.download('brown', quiet=True)
nltk.download('averaged_perceptron_tagger_eng', quiet=True)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

switchcase = None # set the case to blank
PGPmsg.POST() # Make sure PGP Keys are Generated (POST = Power On Self Test)

try:
    open('config.json', 'r')
except:
    print('Error: config.json doesn\'t Exist, Please redownload the project. Exiting...')
    t.sleep(3)
    exit()

with open('config.json', 'r', encoding='utf-8') as f:
    config_dictionary = json.load(f)

global key_map # make key map global so i dont have to pass it in and out of functions
key_map = list(config_dictionary.values())

def list_generate(file_to_write):
    class pt:
        @staticmethod
        def A():
            crs = ['@', '_', '!', '%', '^', '&', '>', '<', '?', '.', '#', '~', '-']
            x = rb(13)
            return crs[x]

    # Word file caches
        def B(): # adverbs
            try:
                with open("av.pkl", "rb") as f:
                    av_ls = pk.load(f)
            except FileNotFoundError:
                av_ls = pre.av()
            av = ch(av_ls)
            return av

        def C(): # verbs
            try:
                with open("v.pkl", "rb") as f:
                    v_ls = pk.load(f)
            except FileNotFoundError:
                v_ls = pre.v()
            v = ch(v_ls)
            return v

        def D(): # middle character
            chs = ['(_)', '[_]', '{_}', '(-)', '[-]', '{-}', '(+)', '[+]', '{+}', '(=)', '[=]', '{=}', '(&)', '[&]', '{&}', '(%)', '[%]', '{%}']
            x = rb(18) # Maximum Security
            return chs[x]

        def E(): #adjective
            try:
                with open("aj.pkl", "rb") as f:
                    aj_ls = pk.load(f)
            except FileNotFoundError:
                aj_ls = pre.aj()
            aj = ch(aj_ls)
            return aj

        def F(): #noun
            try:
                with open("n.pkl", "rb") as f:
                    n_ls = pk.load(f)
            except FileNotFoundError:
                n_ls = pre.n()
            n = ch(n_ls)
            return n

        def G(): # character either side of the end part
            c1 = ['(#', '[#', '{#', '($', '[$', '{$', '(=', '[=', '{='] # Security LV.1 could be index 0-2 and Security LV 2 could be index 3-11
            mpr = {'(#': ')', '[#': ']', '{#': '}', '($': ')', '[$': ']', '{$': '}', '(=': ')', '[=': ']', '{=': '}'}
            a = rb(9) # Maximum Security
            l = c1[a]
            r = mpr[l]
            return l, r

        def H():
            return rb(90000) + 10000 # Maximum Security, rb is randbelow and +10000 is ofset (starting at)

    def joiner(file_name):
            data = []
            done = 0
            print("Verbose: Making Passwords..")
            for i in range(1028): # make 1028 passwords
                    a = pt.A()
                    b = pt.B()
                    c = pt.C()
                    d = pt.D()
                    e = pt.E()
                    f = pt.F()
                    lr = pt.G()
                    gL = lr[0]
                    g = pt.H()
                    gR = lr[1]
                    finished_password = f'{a}{b.title()}{c.title()}{d}{e.title()}{f.title()}{str(gL)}{g}{str(gR)}'
                    done += 1
                    print(f'Made {done} of 1028')
                    data.append(finished_password)
                
            with open(f'Vault/{file_name}.json', 'w') as f:
                    json.dump(data, f, indent=4)
                    print("Data Successfully Written!")
    
    joiner(file_to_write)
    with open(f'Vault/{file_to_write}.json', 'r') as f:
        data = json.load(f)

# Unicode Code - Character Key:
# u+200b is ZWSP (Zero Width Space)
# u+200c is ZWNJ (Zero Width Non Joiner)
# u+200d is ZWJ (Zero Width Joiner)
# u+2060 is WJ (Word Joiner)
# u+200e is LTRM (Left To Right Mark) who is mark, whys he so important??
# u+200f is RTLM (Right To Left Mark) I still dont know who mark is :(
# u+2066 is LTRI (Left To Right Isolate)
# u+2067 is RTLI (Right To Left Isolate)
# u+2068 is FSI (First Strong Isolate)
# u+2069 is PDI (Pop Directional Isolate)
# u+180e is Mongolian Vowel Separator
# u+feff is ZWNBS (Zero Width Breaking Space)
# u+202a is LRE (Left [to] Right Embedding)
# u+202b is RLE (Right [to] Left Embedding)
# u+206a is Inhibit Symmetric Swapping
# u+206b is Active Symmetric Swapping

# in config.json you can change these around, your options for each are:
# \u206b,\u206a,\u202b,\u202a,\ufeff,\u180e,\u2069,\u2068,\u2067,\u2066,\u200f,\u200e,\u2060,\u200d,\u200c,\u200b
# there can only be 1 per nibble (4 bits e.g. 1011)


def hide_text(text):
    binary_data = ''.join(format(ord(c), '08b') for c in text)
    hidden_chars = []
    for i in range(0, len(binary_data), 4):
        four_bit_part = binary_data[i:i+4]  # Break into 4 parts
        index_position = int(four_bit_part, 2) # convert binary to integer
        hidden_chars.append(key_map[index_position])
    return ''.join(hidden_chars)

    # Old method using only 2 chars

    # Convert string to a sequence of 0s and 1s
    #binary_data = ''.join(format(ord(c), '08b') for c in text)
    
    # Map 0 to ZWSP (\u200b) and 1 to ZWJ (\u200d)
    #hidden = binary_data.replace('0', '\u200b').replace('1', '\u200d')



def show_text(text):
    binary_chunks = []
    for char in text: # Read the hidden text character by character
        if char in key_map:
            index = key_map.index(char) # Find the index of this char
            four_bit_part = format(index, '04b') # Convert into a 4-bit binary string (padded with 0's)
            binary_chunks.append(four_bit_part)
            
    full_binary = ''.join(binary_chunks) # Combine all 4-bit parts into one massive binary string
    decoded_string = [] # Break the binary string back into 8-bit bytes and convert to actual characters
    for i in range(0, len(full_binary), 8):
        byte_part = full_binary[i:i+8] # Convert 8-bit binary string to integer, then integer to character
        decoded_string.append(chr(int(byte_part, 2)))
    return ''.join(decoded_string)

def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)  # 256-bit salt for extra entropy
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_files_aes(plaintext, password): # FOR ENCRYPTING FILES ONLY
    salt = os.urandom(32) # Generate a random 256-bit salt (32 bytes for extra entropy) also to add seasoning :P
    key, _ = derive_key_from_password(password, salt) # Derive a strong 256-bit key
    iv = os.urandom(12)  # Generate a 12-byte IV (Nonce) as required by AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())# Create AES-GCM cipher
    aad = os.urandom(32)  # Generate a random AAD (Associated Data) for noise

    encryptor = cipher.encryptor() # Encrypt the plaintext with the authentication tag
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    encrypted_data = base64.b64encode(salt + iv + aad + ciphertext + encryptor.tag) # Combine salt, IV, AAD, ciphertext, and tag
    return encrypted_data


def encrypt_aes(plaintext, password): # FOR ENCRYPTING TEXT ONLY
    salt = os.urandom(32)  # Generate a random 256 bit salt (32 bytes for extra entropy)
    key, _ = derive_key_from_password(password, salt) # Derive a strong 256-bit key
    iv = os.urandom(12)  # Generate a 12-byte IV (Nonce) as required by AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()) # Create AES-GCM cipher
    aad = os.urandom(32)  # Generate a random AAD (Associated Data)

    encryptor = cipher.encryptor() # Encrypt the plaintext with the authentication tag
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    encrypted_data = base64.b64encode(salt + iv + aad + ciphertext + encryptor.tag) # Combine salt, IV, AAD, ciphertext, and tag
    return encrypted_data.decode()

def decrypt_aes(encrypted_data, password): # FOR DECRYPTING FILES AND TEXT
    encrypted_data = base64.b64decode(encrypted_data) # Decode from Base64

    salt = encrypted_data[:32]  # 32-byte salt
    iv = encrypted_data[32:44]  # 12-byte IV
    aad = encrypted_data[44:76]  # 32-byte AAD
    ciphertext = encrypted_data[76:-16]  # Ciphertext
    tag = encrypted_data[-16:]  # 16-byte Authentication Tag
    key, _ = derive_key_from_password(password, salt) # Derive the key using the same salt (NaCl of course)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()) # Create cipher object
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)
    decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize() # Decrypt and verify authentication tag
    decrypted_string = decrypted_plaintext.decode('utf-8')
    return decrypted_plaintext.decode('utf-8')

def overwrite_vault(filepath, content):
    json_string = json.dumps(content) # contents is a list at this stage
    with open(filepath, 'w') as f:
            f.write(json_string)
    print(f"\nFile {filepath} has been overwritten.")

# Original tool built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6

###################################################################################################################
print("\n-- [ This tool was made by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6 ] --")
def message_blur(session_info, message_blur_running):
    while message_blur_running == 1:
        try:
            vault_name = session_info[0]
            pgp_name = session_info[1]
            print(f'Your current session is using {vault_name}\'s Vault and {pgp_name}.pgp')
            change_ask = input("Input \'edit\' to Change session or Press Enter to Continue with current session").strip() or None # Default to None if nothing is entered
            if change_ask.lower() == "edit":
                name = input("\nPlease Enter the name of the Person who\'s password list to use for this session:\n")
                try:
                    open(f'Vault/{name}.json', 'r')
                except:
                    print("Error 404: Vault File Not Found")
                    message_blur_running = 0
                    session_info.clear()
                    return message_blur_running
                with open(f'Vault/{name}.json', 'r') as named_vault:
                        sharedvault = json.loads(named_vault)
                        
                    # Now you have unlocked the vault to reference passwords between chosen person

                pub = input("\nFriends's public key name? (without .asc)\n")
                try:
                    open(f'PGPKeys/{pub}.asc', 'rb')
                except:
                    print("Error 404: PGP File Not Found")
                    message_blur_running = 0
                    session_info.clear()
                    return message_blur_running
                full_file = f'{pub}.asc' #Receivers key
                friend_key_location = "PGPKeys/" + str(full_file)
                
            elif change_ask is None:
                pass

            else:
                print("Invalid Option")
                print("")
                return
        except IndexError:
            name = input("\nPlease Enter the name of the Person who\'s password list to use for this session:\n")
            
            try:
                open(f'Vault/{name}.json', 'r')
            except:
                print("Error 404: Vault File Not Found")
                message_blur_running = 0
                session_info.clear()
                return message_blur_running
                
            with open(f'Vault/{name}.json', 'r') as named_vault:
                try:
                    sharedvault = json.loads(named_vault)
                except:
                    print(f'{name}\'s Vault is Corrupt, Please Regenerate it')
                    print("")
                    message_blur_running = 0
                    session_info.clear()
                    return message_blur_running

            pub = input("\nFriends's public key name? (without .asc)\n")
            try:
                open(f'PGPKeys/{pub}.asc', 'rb')
            except:
                print("Error 404: PGP File Not Found")
                message_blur_running = 0
                session_info.clear()
                return message_blur_running
            full_file = f'{pub}.asc' #Receivers key
            friend_key_location = "PGPKeys/" + str(full_file)
            
        reference_number = secrets.randbelow(len(sharedvault)) # Get a secure random number | we append this number to the end
        plaintext = input("\nWhat is your message? \n")
        try:
            password = sharedvault[int(reference_number)]
        except:
            print("Error: {name}\'s Vault is Corrupt, Please Regenate it")
            print("")
            message_blur_running = 0
            session_info.clear()
            return message_blur_running
        encrypted_msg = encrypt_aes(plaintext, password)
        sharedvault.pop(int(reference_number)) # delete the password so it cant be reused also pop doesn't need assignment as it updates the variable its being used on
        t.sleep(5)
        post_pop_length = len(sharedvault) # also append this which is length of list after removal
        encrypted_msg = f'{encrypted_msg}:{reference_number}_{post_pop_length}'
        print(f'\nYour List is now {post_pop_length} entries long\n\n\n')

        private_key_location = "PGPKeys/private.asc" # Personal private PGP key location
        try:
            open(f'PGPKeys/private.asc', 'rb')
        except:
            print("Error 404: Private Key Renamed or Deleted")
            message_blur_running = 0
            session_info.clear()
            return message_blur_running
        msg = encrypted_msg
        run_pgp = PGPmsg.enc(private_key_location,friend_key_location,msg)
        message = hide_text(str(run_pgp))

        print(f'Encoded: >{message}<')

        overwrite_vault(f'Vault/{name}.json', sharedvault)
        password = ""
        sharedvault = ""

        ask_back = input("Press enter to continue encrypting messages or type \'exit\' to go Back\n").strip() or None
        if ask_back is None:
            continue
        elif ask_back.lower() == "exit":
            session_info.clear()
            message_blur_running = 0
            return message_blur_running

        else:
            print("Invalid Option")
            print("")
            session_info.clear()
            message_blur_running = 0
            return message_blur_running
        
##################################################################################################################
def message_unblur(session_info, message_unblur_running):
    while message_unblur_running == 1:
        try:
            vault_name = session_info[0]
            pgp_name = session_info[1]
            print(f'Your current session is using {vault_name}\'s Vault and {pgp_name}.pgp')
            change_ask = input("Input \'edit\' to Change session or Press Enter to Continue with current session").strip() or None # Default to None if nothing is entered
            if change_ask.lower() == "edit":
                name = input("\nPlease Enter the name of the Person who\'s list to use for this session:\n")
                try:
                    open(f'Vault/{name}.json', 'r')
                except:
                    print("Error 404: Vault File Not Found")
                    message_unblur_running = 0
                    session_info.clear()
                    return message_unblur_running
                with open(f'Vault/{name}.json', 'r') as named_vault:
                    try:
                        sharedvault = json.loads(named_vault)
                    except:
                        print(f'{name}\'s Vault is Corrupt or Desynced, Please Regenerate it')
                        print("")
                        message_unblur_running = 0
                        session_info.clear()
                        return message_unblur_running
                    # Now you have unlocked the vault to reference passwords between chosen person

                senders_key = input("Name of sender's public key for later verification (without .asc)?\n")
                try:
                    open(f'PGPKeys/{pub}.asc', 'rb')
                except:
                    print("Error 404: PGP File Not Found")
                    message_unblur_running = 0
                    session_info.clear()
                    return message_unblur_running
        
                full_file = f'{senders_key}.asc' #senders key
                complete_path = "PGPKeys/" + str(full_file)
                
            elif change_ask is None:
                pass

            else:
                print("Invalid Option")
                print("")
                session_info.clear()
                message_unblur_running = 0
                return message_unblur_running
            
        except IndexError:
            name = input("\nPlease Enter the name of the Person who\'s list to use for this session:\n")
            try:
                open(f'Vault/{name}.json', 'r')
            except:
                print("Error 404: Vault File Not Found")
                message_unblur_running = 0
                session_info.clear()
                return message_unblur_running
                
            with open(f'Vault/{name}.json', 'r') as named_vault:
                try:
                    sharedvault = json.loads(named_vault)
                except:
                    print(f'{name}\'s Vault is Corrupt, Please Regenerate it')
                    print("")
                    message_unblur_running = 0
                    session_info.clear()
                    return message_unblur_running
                # Now you have unlocked the vault to reference passwords between chosen person

            senders_key = input("Name of sender's public key for later verification (without .asc)?\n")
            try:
                open(f'PGPKeys/{senders_key}.asc', 'rb')
            except:
                print("Error 404: PGP File Not Found")
                message_unblur_running = 0
                session_info.clear()
                return message_unblur_running
                
            full_file = f'{senders_key}.asc' # Sender's PGP key
            complete_path = "PGPKeys/" + str(full_file)
            session_info = [f'{name}', f'{senders_key}'] # save the name of the current recievers vault and pgp key
            
        ciphertext = input("\nPlease enter your ciphertext:\n")
        try:
            ciphertext = show_text(ciphertext)
        except:
            print("Error, Ciphertext is corrupt or Incorrect Sender was used!")
            print("")
            message_unblur_running = 0
            session_info.clear()
            return message_unblur_running

        try:
            open(f'PGPKeys/private.asc', 'rb')
        except:
            print("Error 404: Private Key Renamed or Deleted")
            message_blur_running = 0
            session_info.clear()
            return message_blur_running
        private_key_location = "PGPKeys/private.asc" # Personal private PGP key location

        try:
            run = PGPmsg.dec(private_key_location,complete_path,ciphertext)
        except:
            print("Error: Message is Corrupt or Incorrect PGP Key used")
            print("")
            message_unblur_running = 0
            session_info.clear()
            return message_unblur_running
            
        decrypted_pgp = run[0]
        verified = run[1]
        #print("Decrypted message:\n", decrypted_pgp.message)
        print("Signature verified:", bool(verified))

        text_seperator_pass_1 = str(decrypted_pgp.message).split(":")
        ciphertext = text_seperator_pass_1[0] # Ciphertext here
        # print(str(ciphertext))
        metadata = text_seperator_pass_1[1]
        text_seperator_pass_2 = metadata.split("_")
        reference = text_seperator_pass_2[0] # Ref Num Here
        post_pop_length = text_seperator_pass_2[1] # Length after Popping here, check after popping

        password = sharedvault[int(reference)]
        decrypted_msg = decrypt_aes(ciphertext, password)
        sharedvault.pop(int(reference)) # delete the password so it cant be reused also pop doesn't need assignment as it updates the variable its being used on
        new_length = len(sharedvault)
        
        if int(new_length) != int(post_pop_length):
            print("Error, Password sync Mismatch")
            hashed = sha256(password.encode('utf-8')).hexdigest()
            print(f'Password Hash: {hashed} | Password Index: {reference}')
            print("\nPlease Compare with Sender\n")

        print(f'Message:\n\n{decrypted_msg}')
        # friend should use list en/decoder tool to unlock and check what's at that position manually

        overwrite_vault(f'Vault/{name}.json', sharedvault)
        
        ask_back = input("Press enter to continue decrypting messages or type \'exit\' to go Back\n").strip() or None
        if ask_back is None:
            continue # loop back
        elif ask_back.lower() == "exit":
            password = ""
            sharedvault = ""
            session_info.clear()
            message_unblur_running = 0
            return message_unblur_running

        else:
            print("Invalid Option")
            print("")
            session_info.clear()
            message_unblur_running = 0
            return message_unblur_running
    
def friends_vault_generator():
    friend_name = input("Please enter your friends name: ")
    try:
        open(f'Vault/BLANK.json', 'r')
    except:
        print("Error 404: Blank Vault not Found, Please Redownload")
        message_blur_running = 0
        message_unblur_running = 0
        session_info.clear()
        return message_blur_running, message_unblur_running
    shutil.copy('Vault/BLANK.json', f'Vault/{friend_name}.json')
    list_generate(f'{friend_name}')
    print("Share file with your friend and tell them to rename it to your name (keep a copy for later)")
    return
        
session_info = []
message_blur_running = 0
message_unblur_running = 0
started = 1

while started == 1:
    try:
        print('\n\n- Welcome to The Encrypter! -\n')
        print('(1) Generate a Friends Shared File')
        print('(2) Encrypt Text')
        print('(3) Decrypt Text')
        print('[Press CTRL+C at any time to return to this Menu]')
        start_menu_choice = input('\n > ')

        if start_menu_choice == "1":
            try:
                friends_vault_generator()
            except KeyboardInterrupt:
                session_info.clear()
                continue
            
        elif start_menu_choice == "2":
            try:                
                try:
                    open(f'PGPKeys/private.asc', 'r')
                    open(f'PGPKeys/public.asc', 'r')
                except:
                    print("Error 404: Private or Public PGP key missing, Please clear private/public(.asc) and restart the program \nExiting in 3 seconds...")
                    t.sleep(3)
                    exit()
                message_blur_running = 1
                message_blur(session_info, message_blur_running)
            except KeyboardInterrupt:
                session_info.clear()
                message_blur_running = 0
                continue
        elif start_menu_choice == "3":
            try:
                try:
                    open(f'PGPKeys/private.asc', 'r')
                    open(f'PGPKeys/public.asc', 'r')
                except:
                    print("Error 404: Private or Public PGP key missing, Please clear private/public(.asc) and restart the program \nExiting in 3 seconds...")
                    t.sleep(3)
                    exit()
                message_unblur_running = 1
                message_unblur(session_info, message_unblur_running)
            except KeyboardInterrupt:
                session_info.clear()
                message_unblur_running = 0
                continue
        else:
            print("Invalid Option!")
            print("")
            continue
        
    except KeyboardInterrupt:
        message_blur_running = 0
        message_unblur_running = 0
        session_info.clear()
        ask_exit = input("Are you sure you want to exit? [Y]es/[N]o: ")
        if ask_exit.lower() == "y":
            exit()
        else:
            continue
# Original tool built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6
