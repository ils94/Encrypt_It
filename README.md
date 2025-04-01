# Encrypt It

A simple Android application for secure text encryption and decryption using a hybrid RSA/AES encryption scheme. Encrypt It allows users to encrypt messages with a contact's public key and decrypt them with their private key, ensuring secure communication.

## Features

- **Hybrid Encryption:** Combines RSA (2048-bit) for key exchange and AES/CBC (256-bit) for message encryption.
- **Contact Management:** Add, remove, and select contacts with their public keys for encryption.
- **Clipboard Integration:** Automatically copies encrypted messages to the clipboard for easy sharing.
- **Key Persistence:** Stores your RSA key pair and contact public keys in `SharedPreferences`.
- **User-Friendly UI:** Simple interface with an `EditText` for messages, buttons for encryption/decryption, and a dropdown for contact selection.

## Prerequisites

- Android Studio (latest stable version recommended)
- Android SDK (API 21 or higher)
- A device or emulator running Android 5.0 (Lollipop) or later

## Usage

1. **Generate or Load Keys:**
   - On first launch, the app generates a 2048-bit RSA key pair and saves it to `SharedPreferences`.
   - View your public key via Menu > "Show My Public Key" and share it with contacts.

2. **Add Contacts:**
   - Menu > "Add Contact."
   - Enter a name and paste their RSA public key (Base64-encoded).
   - Save to store the contact.

3. **Encrypt a Message:**
   - Type your message in the text field.
   - Select a contact from the dropdown.
   - Click "Encrypt" to encrypt the message and copy it to the clipboard.

4. **Decrypt a Message:**
   - Paste an encrypted message (format: `encryptedAesKey:iv:encryptedMessage`) into the text field.
   - Click "Decrypt" to reveal the original text.

5. **Manage Contacts:**
   - Menu > "Remove Contact" to delete contacts from the list.

## Security Notes

- **Key Size:** Uses 2048-bit RSA and 256-bit AES for strong encryption.
- **IV:** Generates a random 16-byte IV for each AES encryption.
- **Padding:** RSA uses PKCS1Padding, AES uses PKCS5Padding.
- **Limitations:** No input validation for public keys—invalid keys may cause encryption failures.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Android Studio and Java.
- Inspired by the need to share text information more securely.

## Download

[Download Encrypt It](https://github.com/ils94/Encrypt_It/releases/download/v1/Encrypt-It-v1.apk)
