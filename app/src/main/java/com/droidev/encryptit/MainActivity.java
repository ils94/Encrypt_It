package com.droidev.encryptit;

import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.method.PasswordTransformationMethod;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    private EditText messageEditText;
    private AutoCompleteTextView contactAutoComplete;
    private KeyPair keyPair;
    private final Map<String, String> contacts = new HashMap<>();
    private SharedPreferences prefs;
    private PublicKey selectedPublicKey;
    private PrivateKey runtimePrivateKey; // Decrypted private key for runtime use

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        View rootView = findViewById(android.R.id.content);
        ViewCompat.setOnApplyWindowInsetsListener(rootView, (view, insets) -> {
            int statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top;
            view.setPadding(
                    view.getPaddingLeft(),
                    statusBarHeight, // empurra tudo para baixo da status bar / ilha
                    view.getPaddingRight(),
                    view.getPaddingBottom()
            );
            return insets;
        });

        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);

        messageEditText = findViewById(R.id.messageEditText);
        contactAutoComplete = findViewById(R.id.contactAutoComplete);
        Button encryptButton = findViewById(R.id.encryptButton);
        Button decryptButton = findViewById(R.id.decryptButton);

        prefs = getSharedPreferences("CryptoPrefs", MODE_PRIVATE);
        initializeKeys();

        // Prompt for password to decrypt private key if it exists
        if (prefs.contains("encryptedPrivateKey")) {
            promptForPasswordToDecrypt();
        }

        // Load contacts from SharedPreferences (excluding key pair entries)
        Map<String, ?> allPrefs = prefs.getAll();
        for (Map.Entry<String, ?> entry : allPrefs.entrySet()) {
            if (!entry.getKey().equals("myPublicKey") && !entry.getKey().equals("encryptedPrivateKey")) {
                contacts.put(entry.getKey(), (String) entry.getValue());
            }
        }

        // Setup autocomplete
        updateAutoComplete();

        contactAutoComplete.setOnItemClickListener((parent, view, position, id) -> {
            String selectedContact = (String) parent.getItemAtPosition(position);
            try {
                selectedPublicKey = loadPublicKeyFromBase64(contacts.get(selectedContact));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        encryptButton.setOnClickListener(v -> encryptMessage());
        decryptButton.setOnClickListener(v -> decryptMessage());
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_show_keys) {
            showPublicKey();
            return true;
        } else if (id == R.id.action_add_contact) {
            showAddContactDialog();
            return true;
        } else if (id == R.id.action_remove_contact) {
            showRemoveContactDialog();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void initializeKeys() {
        if (prefs.contains("myPublicKey") && prefs.contains("encryptedPrivateKey")) {
            // Load public key (private key will be decrypted later)
            try {
                String pubKeyBase64 = prefs.getString("myPublicKey", "");
                byte[] pubKeyBytes = Base64.decode(pubKeyBase64, Base64.DEFAULT);
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey publicKey = kf.generatePublic(pubSpec);
                keyPair = new KeyPair(publicKey, null); // Private key loaded later
            } catch (Exception e) {
                e.printStackTrace();
                generateRSAKeyPair(); // Fallback to generating new keys
            }
        } else {
            generateRSAKeyPair(); // Generate and save new keys
        }
    }

    private void generateRSAKeyPair() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        EditText passwordInput = new EditText(this);
        passwordInput.setHint(R.string.generate_rsa_key_pair_hint);
        passwordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());

        builder.setView(passwordInput)
                .setTitle(R.string.generate_rsa_key_pair_builder_title)
                .setPositiveButton(R.string.button_save, null)
                .setCancelable(false);

        AlertDialog dialog = builder.create();
        dialog.show();

        // Override the positive button click listener to prevent auto-dismiss
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String password = passwordInput.getText().toString();
            if (password.isEmpty()) {
                Toast.makeText(this, R.string.generate_rsa_key_pair_builder_toast_1, Toast.LENGTH_SHORT).show();
                return; // Dialog won't dismiss
            }

            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                keyPair = keyGen.generateKeyPair();

                String pubKeyBase64 = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.DEFAULT);
                encryptAndStorePrivateKey(keyPair.getPrivate(), password);

                SharedPreferences.Editor editor = prefs.edit();
                editor.putString("myPublicKey", pubKeyBase64);
                editor.apply();

                dialog.dismiss(); // Only dismiss when successful
            } catch (Exception e) {
                e.printStackTrace();
                Toast.makeText(this, R.string.generate_rsa_key_pair_builder_toast_2 + " " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
    }

    private void encryptAndStorePrivateKey(PrivateKey privateKey, String password) throws Exception {
        // Generate a random IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Generate a random salt for PBKDF2
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        // Derive AES key from password using PBKDF2
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey aesKey = new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");

        // Encrypt private key with AES-256-CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());

        // Store IV, salt, and encrypted key
        String storedValue = Base64.encodeToString(iv, Base64.DEFAULT) + ":" +
                Base64.encodeToString(salt, Base64.DEFAULT) + ":" +
                Base64.encodeToString(encryptedPrivateKey, Base64.DEFAULT);
        prefs.edit().putString("encryptedPrivateKey", storedValue).apply();
    }

    private void promptForPasswordToDecrypt() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        EditText passwordInput = new EditText(this);
        passwordInput.setHint(R.string.prompt_for_password_to_decrypt_hint);
        passwordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
        builder.setView(passwordInput)
                .setTitle(R.string.prompt_for_password_to_decrypt_builder_title)
                .setPositiveButton(R.string.unlock_button, (dialog, which) -> {
                    String password = passwordInput.getText().toString();
                    try {
                        runtimePrivateKey = decryptPrivateKey(password);
                        keyPair = new KeyPair(keyPair.getPublic(), runtimePrivateKey);
                        Toast.makeText(this, R.string.prompt_for_password_to_decrypt_toast_1, Toast.LENGTH_SHORT).show();
                    } catch (Exception e) {
                        e.printStackTrace();
                        Toast.makeText(this, R.string.prompt_for_password_to_decrypt_toast_1 + " " + e.getMessage(), Toast.LENGTH_LONG).show();
                        promptForPasswordToDecrypt(); // Retry on failure
                    }
                })
                .setCancelable(false)
                .show();
    }

    private PrivateKey decryptPrivateKey(String password) throws Exception {
        String storedValue = prefs.getString("encryptedPrivateKey", "");
        String[] parts = storedValue.split(":");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid encrypted key format");

        byte[] iv = Base64.decode(parts[0], Base64.DEFAULT);
        byte[] salt = Base64.decode(parts[1], Base64.DEFAULT);
        byte[] encryptedPrivateKey = Base64.decode(parts[2], Base64.DEFAULT);

        // Derive AES key from password using PBKDF2
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey aesKey = new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");

        // Decrypt private key
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedPrivateKey);

        // Reconstruct PrivateKey object
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(decryptedKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(privSpec);
    }

    private void encryptMessage() {
        if (selectedPublicKey == null) {
            Toast.makeText(this, R.string.select_a_contact_first_toast, Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            String message = messageEditText.getText().toString();

            // Generate a random AES key (256-bit)
            byte[] aesKeyBytes = new byte[32];
            new SecureRandom().nextBytes(aesKeyBytes);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Generate a random IV (16 bytes for AES/CBC)
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Encrypt the message with AES/CBC
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());

            // Encrypt the AES key with RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, selectedPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKeyBytes);

            // Combine encrypted key, IV, and message (Base64 encoded)
            String encryptedText = Base64.encodeToString(encryptedAesKey, Base64.DEFAULT) + ":" +
                    Base64.encodeToString(ivBytes, Base64.DEFAULT) + ":" +
                    Base64.encodeToString(encryptedMessage, Base64.DEFAULT);

            // Copy encrypted text to clipboard
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(encryptedText);
            Toast.makeText(this, R.string.encrypted_message_copied_to_clipboard_toast, Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, R.string.encryption_failed_toast + " " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void decryptMessage() {
        if (runtimePrivateKey == null) {
            Toast.makeText(this, "Private key not unlocked yet", Toast.LENGTH_SHORT).show();

            if (prefs.contains("encryptedPrivateKey")) {
                promptForPasswordToDecrypt();
            }
        }

        try {
            String encryptedText = messageEditText.getText().toString();
            String[] parts = encryptedText.split(":", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid encrypted message format");
            }

            // Extract encrypted AES key, IV, and message
            byte[] encryptedAesKey = Base64.decode(parts[0], Base64.DEFAULT);
            byte[] ivBytes = Base64.decode(parts[1], Base64.DEFAULT);
            byte[] encryptedMessage = Base64.decode(parts[2], Base64.DEFAULT);

            // Decrypt the AES key with RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, runtimePrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Decrypt the message with AES/CBC
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            byte[] decryptedBytes = aesCipher.doFinal(encryptedMessage);
            messageEditText.setText(new String(decryptedBytes));
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, R.string.decryption_failed_toast + " " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void showAddContactDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View view = getLayoutInflater().inflate(R.layout.dialog_add_contact, null);

        EditText nameEditText = view.findViewById(R.id.contactNameEditText);
        EditText keyEditText = view.findViewById(R.id.contactKeyEditText);

        builder.setView(view)
                .setCancelable(false)
                .setTitle(R.string.add_new_contact_alertdialog_title)
                .setPositiveButton(R.string.button_save, (dialog, which) -> {
                    String name = nameEditText.getText().toString();
                    String key = keyEditText.getText().toString();

                    if (name.isEmpty() || key.isEmpty()) {
                        Toast.makeText(this, R.string.add_new_contact_toast_1, Toast.LENGTH_SHORT).show();
                        return;
                    }

                    contacts.put(name, key);
                    prefs.edit().putString(name, key).apply();
                    updateAutoComplete();

                    Toast.makeText(this, R.string.add_new_contact_toast_2, Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(R.string.cancel_button, null)
                .show();
    }

    private void showRemoveContactDialog() {
        if (contacts.isEmpty()) {
            Toast.makeText(this, R.string.no_contacts_to_remove_toast, Toast.LENGTH_SHORT).show();
            return;
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.remove_contact_alertdialog_title);
        builder.setCancelable(false);

        RecyclerView recyclerView = new RecyclerView(this);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        ArrayList<String> contactList = new ArrayList<>(contacts.keySet());
        ContactAdapter adapter = new ContactAdapter(contactList);
        recyclerView.setAdapter(adapter);

        builder.setView(recyclerView)
                .setPositiveButton(R.string.remove_contact_remove_button, (dialog, which) -> {
                    List<String> contactsToRemove = adapter.getSelectedContacts();

                    if (contactsToRemove.isEmpty()) {
                        Toast.makeText(this, R.string.remove_contact_toast_1, Toast.LENGTH_SHORT).show();
                        return;
                    }

                    new AlertDialog.Builder(this)
                            .setTitle(R.string.remove_contact_confirm_alertdialog_title)
                            .setCancelable(false)
                            .setMessage(getString(R.string.remove_contact_confirm_alertdialog_message_1) + " " +
                                    contactsToRemove.size() + " " + getString(R.string.remove_contact_confirm_alertdialog_message_2))
                            .setPositiveButton(R.string.remove_contact_confirm_alertdialog_yes, (confirmDialog, confirmWhich) -> {
                                SharedPreferences.Editor editor = prefs.edit();
                                for (String contact : contactsToRemove) {
                                    contacts.remove(contact);
                                    editor.remove(contact);
                                    if (selectedPublicKey != null && contacts.get(contact) != null &&
                                            selectedPublicKey.equals(loadPublicKeyFromBase64Silently(contacts.get(contact)))) {
                                        selectedPublicKey = null;
                                    }
                                }
                                editor.apply();
                                updateAutoComplete();

                                Toast.makeText(this, contactsToRemove.size() + " " + getString(R.string.remove_contact_toast_2), Toast.LENGTH_SHORT).show();
                            })
                            .setNegativeButton(R.string.remove_contact_confirm_alertdialog_no, null)
                            .show();
                })
                .setNegativeButton(R.string.remove_contact_cancel_button, null)
                .show();
    }

    private PublicKey loadPublicKeyFromBase64Silently(String keyBase64) {
        try {
            return loadPublicKeyFromBase64(keyBase64);
        } catch (Exception e) {
            return null;
        }
    }

    private void updateAutoComplete() {
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_dropdown_item_1line, contacts.keySet().toArray(new String[0]));
        contactAutoComplete.setAdapter(adapter);
    }

    private void showPublicKey() {
        if (keyPair == null || keyPair.getPublic() == null) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.public_key_alertdialog_error_title)
                    .setMessage(R.string.public_key_alertdialog_error_message)
                    .setPositiveButton(R.string.public_key_alertdialog_error_ok, null)
                    .setCancelable(false)
                    .show();
            return;
        }

        String publicKey = prefs.getString("myPublicKey", "Not found");

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.public_key_alertdialog_title)
                .setCancelable(false)
                .setMessage(publicKey)
                .setPositiveButton(R.string.public_key_alertdialog_copy_button, (dialog, which) -> {
                    ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    clipboard.setText(publicKey);
                    Toast.makeText(this, R.string.public_key_alertdialog_toast, Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(R.string.public_key_alertdialog_close_button, null)
                .show();
    }

    private PublicKey loadPublicKeyFromBase64(String keyBase64) throws Exception {
        byte[] keyBytes = Base64.decode(keyBase64, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}