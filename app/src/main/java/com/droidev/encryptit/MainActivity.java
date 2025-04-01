package com.droidev.encryptit;

import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

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
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    private EditText messageEditText;
    private AutoCompleteTextView contactAutoComplete;
    private KeyPair keyPair;
    private Map<String, String> contacts = new HashMap<>();
    private SharedPreferences prefs;
    private PublicKey selectedPublicKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        messageEditText = findViewById(R.id.messageEditText);
        contactAutoComplete = findViewById(R.id.contactAutoComplete);
        Button encryptButton = findViewById(R.id.encryptButton);
        Button decryptButton = findViewById(R.id.decryptButton);

        prefs = getSharedPreferences("CryptoPrefs", MODE_PRIVATE);
        initializeKeys();

        // Load contacts from SharedPreferences (excluding key pair entries)
        Map<String, ?> allPrefs = prefs.getAll();
        for (Map.Entry<String, ?> entry : allPrefs.entrySet()) {
            if (!entry.getKey().equals("myPublicKey") && !entry.getKey().equals("myPrivateKey")) {
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
        if (prefs.contains("myPublicKey") && prefs.contains("myPrivateKey")) {
            // Load existing keys
            try {
                String pubKeyBase64 = prefs.getString("myPublicKey", "");
                byte[] pubKeyBytes = Base64.decode(pubKeyBase64, Base64.DEFAULT);
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey publicKey = kf.generatePublic(pubSpec);

                String privKeyBase64 = prefs.getString("myPrivateKey", "");
                byte[] privKeyBytes = Base64.decode(privKeyBase64, Base64.DEFAULT);
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
                PrivateKey privateKey = kf.generatePrivate(privSpec);

                keyPair = new KeyPair(publicKey, privateKey);
            } catch (Exception e) {
                e.printStackTrace();
                generateRSAKeyPair(); // Fallback to generating new keys
            }
        } else {
            generateRSAKeyPair(); // Generate and save new keys
        }
    }

    private void generateRSAKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyPair = keyGen.generateKeyPair();

            String pubKeyBase64 = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.DEFAULT);
            String privKeyBase64 = Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.DEFAULT);
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("myPublicKey", pubKeyBase64);
            editor.putString("myPrivateKey", privKeyBase64);
            editor.apply();
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, R.string.key_generation_failed_toast + " " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
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
            rsaCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
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
                .setPositiveButton(R.string.add_new_contact_save_button, (dialog, which) -> {
                    String name = nameEditText.getText().toString();
                    String key = keyEditText.getText().toString();

                    if (name.isEmpty() || key.isEmpty()) {

                        Toast.makeText(this, R.string.add_new_contact_toast, Toast.LENGTH_SHORT).show();
                        return;
                    }

                    contacts.put(name, key);
                    prefs.edit().putString(name, key).apply();
                    updateAutoComplete();
                })
                .setNegativeButton(R.string.add_new_contact_cancel_button, null)
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

        ListView listView = new ListView(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_list_item_multiple_choice, new ArrayList<>(contacts.keySet()));
        listView.setAdapter(adapter);
        listView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);

        builder.setView(listView)
                .setPositiveButton(R.string.remove_contact_remove_button, (dialog, which) -> {
                    ArrayList<String> contactsToRemove = new ArrayList<>();
                    for (int i = 0; i < listView.getCount(); i++) {
                        if (listView.isItemChecked(i)) {
                            contactsToRemove.add(adapter.getItem(i));
                        }
                    }

                    if (contactsToRemove.isEmpty()) {
                        Toast.makeText(this, R.string.remove_contact_toast_1, Toast.LENGTH_SHORT).show();
                        return;
                    }

                    new AlertDialog.Builder(this)
                            .setTitle(R.string.remove_contact_confirm_alertdialog_title)
                            .setCancelable(false)
                            .setMessage(R.string.remove_contact_confirm_alertdialog_message_1 + " " + contactsToRemove.size() + " " + R.string.remove_contact_confirm_alertdialog_message_2)
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
                                Toast.makeText(this, contactsToRemove.size() + " " + R.string.remove_contact_toast_2, Toast.LENGTH_SHORT).show();
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
        if (keyPair == null) {
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