# Encrypt It

A simple Android application for secure text and file encryption and decryption using a hybrid RSA/AES encryption scheme. Encrypt It allows users to encrypt messages and files with a contact's public key so they can decrypt it with their private key, ensuring secure communication and file sharing.

## Features

-   **Hybrid Encryption:** Combines RSA (2048-bit) for key exchange and AES/CBC (256-bit) for message encryption.
-   **Contact Management:** Add, remove, and select contacts with their public keys for encryption.
-   **Key Import/Export:** Export and import your public and encrypted private keys to/from a JSON file for backup or transfer.
-   **Contact Import/Export:** Export and import your contact list with their public keys to/from a JSON file.
-   **Clipboard Integration:** Automatically copies encrypted messages to the clipboard for easy sharing.
-   **Key Persistence:** Stores your RSA key pair and contact public keys in `SharedPreferences`.
-   **User-Friendly UI:** Simple interface with an `EditText` for messages, buttons for encryption/decryption, and a dropdown for contact selection.
-   **Encrypted Private Key:** The user's private key is encrypted and saved locally. The user must use the same password to decrypt their private key in order to use the app.
-   **File Encryption and Decryption:** Encrypt a file using your contact's public key so that only they can decrypt it with their private key.
-   **Sign and Verify Messages:** Digitally sign your messages with your private key and verify messages from contacts using their public keys.

## Usage

1.  **Generate or Load Keys:**
    
    -   On first launch, the app generates a 2048-bit RSA key pair and saves it to `SharedPreferences`.
    -   The user will be prompted to set a password to encrypt their private key, and again when opening the app to decrypt the private key.
    -   View your public key via Menu > Keys > "Show My Public Key" and share it with contacts.
    -   Export your public and encrypted private keys to a JSON file via Menu > Keys > "Export Keys".
    -   Import keys from a JSON file via Menu > Keys > "Import Keys" (requires the same password used for encryption).
2.  **Add Contacts:**
    
    -   Menu > Contacts > "Add Contact".
    -   Enter a name and paste their RSA public key.
    -   Save to store the contact.
    -   Export all contacts and their public keys to a JSON file via Menu > Contacts > "Export Contacts".
    -   Import contacts from a JSON file via Menu > Contacts > "Import Contacts".
3.  **Encrypt a Message:**
    
    -   Type your message in the text field.
    -   Enter the contact name and select it from the dropdown menu.
    -   Click "Encrypt" to encrypt the message and copy it to the clipboard.
4.  **Decrypt a Message:**
    
    -   Paste an encrypted message into the text field.
    -   Click "Decrypt" to reveal the original text.
5.  **Manage Contacts:**
    
    -   Menu > Contacts > "Remove Contact" to delete contacts from the list.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Download

[Download Encrypt It](https://github.com/ils94/Encrypt_It/releases/download/v7/Encrypt-It-v7.apk)
