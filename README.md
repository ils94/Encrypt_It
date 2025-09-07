# Encrypt It

A simple Android application for secure text encryption and decryption using a hybrid RSA/AES encryption scheme. Encrypt It allows users to encrypt messages with a contact's public key so they can decrypt it with their private key, ensuring secure communication.

## Features

- **Hybrid Encryption:** Combines RSA (2048-bit) for key exchange and AES/CBC (256-bit) for message encryption.
- **Contact Management:** Add, remove, and select contacts with their public keys for encryption.
- **Clipboard Integration:** Automatically copies encrypted messages to the clipboard for easy sharing.
- **Key Persistence:** Stores your RSA key pair and contact public keys in `SharedPreferences`.
- **User-Friendly UI:** Simple interface with an `EditText` for messages, buttons for encryption/decryption, and a dropdown for contact selection.
- **Encrypted Private Key:** The user's private key is encrypted and saved locally. The user must use the same password to decrypt their private key in order to use the app.

## Usage

1. **Generate or Load Keys:**
   - On first launch, the app generates a 2048-bit RSA key pair and saves it to `SharedPreferences`.
   - The user will be prompted to set a password to encrypt their private key, and again when opening the app to decrypt the private key. 
   - View your public key via Menu > "Show My Public Key" and share it with contacts.

3. **Add Contacts:**
   - Menu > "Add Contact."
   - Enter a name and paste their RSA public key.
   - Save to store the contact.

4. **Encrypt a Message:**
   - Type your message in the text field.
   - Select a contact from the dropdown.
   - Click "Encrypt" to encrypt the message and copy it to the clipboard.

5. **Decrypt a Message:**
   - Paste an encrypted message into the text field.
   - Click "Decrypt" to reveal the original text.

6. **Manage Contacts:**
   - Menu > "Remove Contact" to delete contacts from the list.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Download

[Download Encrypt It](https://github.com/ils94/Encrypt_It/releases/download/v3/encryptit.apk)
