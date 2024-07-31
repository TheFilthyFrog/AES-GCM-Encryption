# AES-GCM-Encryption
AES-GCM Encryption Script securely encrypts and decrypts text using AES-256 in Galois/Counter Mode. 

AES-GCM Encryption Script: Overview- Purpose:
    - The script allows users to securely encrypt and decrypt text using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
    - AES-GCM provides both confidentiality (encryption) and authenticity (authentication) for data.
    
- Components:
    - Key Derivation: The user's password is used to derive a unique encryption key.
    - Encryption: Plaintext is encrypted using AES-GCM with a random nonce.
    - Decryption: Ciphertext is decrypted back to plaintext.
      
- Security Features:
    - Key Strength: The script uses a 256-bit key derived from the user's password, which is considered secure.
    - Nonce: A random nonce ensures that the same plaintext encrypted multiple times produces different ciphertexts.
    - Authentication Tag: GCM provides integrity and authenticity by including an authentication tag with the ciphertext.
      
How to Use the Script:- Requirements:
    - Ensure you have Python installed on your system.
    - The cryptography library is required. Install it using pip install cryptography.
      
- Running the Script:
    - Save the code snippet as a Python file (e.g., aes_gcm.py).
    - Open a terminal or command prompt.
    - Navigate to the directory containing the script.
    - Run the script using python aes_gcm.py.
      
- Choose Operation:
    - The script will prompt you to choose between encryption ('e') or decryption ('d').
      
- Encryption:
    - If you choose encryption ('e'):
        - Enter Password: *******
        - Enter the plaintext you want to encrypt.
        - The script will generate a random salt, derive a key from your password, and encrypt the data.
        - It will display the base64-encoded encrypted text.
          
    - Example:

Do you want to (e)ncrypt or (d)ecrypt? (e/d): e
Enter Password: *******
Enter text to encrypt: Hello, world!
Encrypted text: <base64-encoded ciphertext>

- Decryption:
    - If you choose decryption ('d'):
        - Enter Password: ******
        - Enter the base64-encoded encrypted text.
        - The script will decode the data, extract the components, derive the key, and decrypt the ciphertext.
        - It will display the original plaintext.
          
    - Example:

Do you want to (e)ncrypt or (d)ecrypt? (e/d): d
Enter Password: ******
Enter text to decrypt: <base64-encoded ciphertext>
Decrypted text: Hello, world!

- Repeat or Exit:
    - After each operation, the script will ask if you want to perform another operation.
    - Type 'y' to continue or 'n' to exit.
      
Security Assessment:- Confidentiality: AES-GCM provides strong confidentiality due to the 256-bit key length.
- Integrity/Authenticity: The authentication tag ensures data integrity and authenticity.
- Password Security: The security depends on the strength of your password. Use a strong, unique password.
- Nonce Reuse: Ensures nonces are never reused for different messages.
  
Remember to keep your password secure and avoid sharing it. Overall, this script provides a good balance of security and usability for encrypting sensitive data.

Feel free to share it with others! 😊

