import sys
import os
import base64
import getpass
import platform
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

print(r''' 
    **********************************************************
    *                                                        *
    *  author - TheFilthyFrog                                *
    *  https://github.com/TheFilthyFrog/AES-GCM-Encryption   *
    *                                                        *
    *             +++                                        *
    *            (o o)                                       *
    *        ooO--(_)--Ooo                                   *
    *                                                        *
    *       Text Encryption                                  *
    *                                                        *
    **********************************************************
  ''')
  
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt(plain_text, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    
    nonce = os.urandom(12)
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    
    encrypted_data = base64.urlsafe_b64encode(salt + nonce + cipher_text + encryptor.tag).decode('utf-8')
    return encrypted_data

def decrypt(encrypted_data, password):
    encrypted_data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
    
    salt, nonce, cipher_text, tag = encrypted_data[:16], encrypted_data[16:28], encrypted_data[28:-16], encrypted_data[-16:]
    
    key = generate_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_data.decode('utf-8')

def get_password(prompt="Enter password: "):
    password = ""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    
    if platform.system() == 'Windows':
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch in {b'\r', b'\n'}:
                break
            elif ch == b'\x08':  # Backspace
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
            else:
                password += ch.decode()
                sys.stdout.write('*')
            sys.stdout.flush()
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                ch = sys.stdin.read(1)
                if ch in {'\n', '\r'}:
                    break
                elif ch == '\x7f':  # Backspace
                    if len(password) > 0:
                        password = password[:-1]
                        sys.stdout.write('\b \b')
                else:
                    password += ch
                    sys.stdout.write('*')
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    print()
    return password.encode()

def main():
    while True:
        choice = input("Do you want to (e)ncrypt or (d)ecrypt? (e/d): ").lower()
        if choice not in ['e', 'd']:
            print("Invalid choice, please enter 'e' to encrypt or 'd' to decrypt.")
            continue
        
        password = get_password()
        
        if choice == 'e':
            plain_text = input("Enter text to encrypt: ")
            encrypted_text = encrypt(plain_text, password)
            print(f"Encrypted text: {encrypted_text}")
        else:
            encrypted_text = input("Enter text to decrypt: ")
            try:
                decrypted_text = decrypt(encrypted_text, password)
                print(f"Decrypted text: {decrypted_text}")
            except Exception as e:
                print(f"An error occurred during decryption: {e}")
        
        another = input("Do you want to perform another operation? (y/n): ").lower()
        if another != 'y':
            break

if __name__ == "__main__":
    main()
