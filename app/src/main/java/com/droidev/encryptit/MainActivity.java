package com.droidev.encryptit;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.method.PasswordTransformationMethod;
import android.util.Base64;
import android.view.GestureDetector;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    private Uri pendingSourceUri = null;
    private boolean pendingEncrypt = false;
    private static final int REQUEST_EXPORT_KEYS = 1001;
    private static final int REQUEST_IMPORT_KEYS = 1002;
    private static final int REQUEST_EXPORT_CONTACTS = 1003;
    private static final int REQUEST_IMPORT_CONTACTS = 1004;

    private static final int REQUEST_ENCRYPT_FILE = 2001;
    private static final int REQUEST_DECRYPT_FILE = 2002;

    private EditText messageEditText;
    private AutoCompleteTextView contactAutoComplete;
    private KeyPair keyPair;
    private final Map<String, String> contacts = new HashMap<>();
    private SharedPreferences prefs;
    private PublicKey selectedPublicKey;
    private PrivateKey runtimePrivateKey;

    private static int tapCount = 0;
    private static long lastTapTime = 0;
    private static final long TRIPLE_TAP_TIMEOUT = 1000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        View rootView = findViewById(android.R.id.content);
        ViewCompat.setOnApplyWindowInsetsListener(rootView, (view, insets) -> {
            int statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top;
            view.setPadding(
                    view.getPaddingLeft(),
                    statusBarHeight,
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

        setupTripleTapListener();

        prefs = getSharedPreferences("CryptoPrefs", MODE_PRIVATE);
        initializeKeys();

        if (prefs.contains("encryptedPrivateKey")) {
            promptForPasswordToDecrypt();
        }

        Map<String, ?> allPrefs = prefs.getAll();
        for (Map.Entry<String, ?> entry : allPrefs.entrySet()) {
            if (!entry.getKey().equals("myPublicKey") && !entry.getKey().equals("encryptedPrivateKey")) {
                contacts.put(entry.getKey(), (String) entry.getValue());
            }
        }

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

    @SuppressLint("ClickableViewAccessibility")
    private void setupTripleTapListener() {
        messageEditText.setOnTouchListener((v, event) -> {
            if (event.getAction() == MotionEvent.ACTION_DOWN) {
                long currentTime = System.currentTimeMillis();

                if (currentTime - lastTapTime > TRIPLE_TAP_TIMEOUT) {
                    tapCount = 0;
                }

                tapCount++;
                lastTapTime = currentTime;

                if (tapCount == 3) {

                    handleTripleTap();
                    tapCount = 0;
                    return true;
                }
            }
            return false;
        });
    }

    private void handleTripleTap() {
        if (!messageEditText.getText().toString().isEmpty()) {
            Toast.makeText(this, R.string.cannot_paste_message_field_not_empty, Toast.LENGTH_SHORT).show();
            return;
        }

        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard.hasPrimaryClip() && Objects.requireNonNull(clipboard.getPrimaryClip()).getItemCount() > 0) {
            CharSequence pastedText = clipboard.getPrimaryClip().getItemAt(0).getText();
            if (pastedText != null && !pastedText.toString().isEmpty()) {
                messageEditText.setText(pastedText);
                decryptMessage();
            } else {
                Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show();
        }
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
        } else if (id == R.id.action_export_keys) {
            exportKeys();
            return true;
        } else if (id == R.id.action_import_keys) {
            importKeys();
            return true;
        } else if (id == R.id.action_export_contacts) {
            exportContacts();
            return true;
        } else if (id == R.id.action_import_contacts) {
            importContacts();
            return true;
        } else if (id == R.id.action_encrypt_file) {
            pickFileToEncrypt();
            return true;
        } else if (id == R.id.action_decrypt_file) {
            pickFileToDecrypt();
            return true;
        } else if (id == R.id.action_sign_message) {
            signMessage();
            return true;
        } else if (id == R.id.action_verify_message) {
            verifyMessage();
            return true;
        } else if (id == R.id.action_clear_message) {
            clearText();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void pickFileToEncrypt() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, REQUEST_ENCRYPT_FILE);
    }

    private void pickFileToDecrypt() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, REQUEST_DECRYPT_FILE);
    }

    private void exportKeys() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, "keys.json");
        startActivityForResult(intent, REQUEST_EXPORT_KEYS);
    }

    private void importKeys() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        startActivityForResult(intent, REQUEST_IMPORT_KEYS);
    }

    private void exportContacts() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, "contacts.json");
        startActivityForResult(intent, REQUEST_EXPORT_CONTACTS);
    }

    private void importContacts() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        startActivityForResult(intent, REQUEST_IMPORT_CONTACTS);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) return;

        Uri uri = data.getData();
        if (uri == null) return;

        try {
            if (requestCode == REQUEST_ENCRYPT_FILE) {
                if (selectedPublicKey == null) {
                    Toast.makeText(this, getString(R.string.select_contact_first), Toast.LENGTH_SHORT).show();
                    return;
                }
                pendingSourceUri = uri;
                pendingEncrypt = true;

                String originalName = getFileName(this, uri);
                String encryptedName = originalName + ".enc";

                Intent createIntent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                createIntent.addCategory(Intent.CATEGORY_OPENABLE);
                createIntent.setType("application/octet-stream");
                createIntent.putExtra(Intent.EXTRA_TITLE, encryptedName);
                startActivityForResult(createIntent, REQUEST_ENCRYPT_FILE + 100);

            } else if (requestCode == REQUEST_ENCRYPT_FILE + 100) {
                if (pendingSourceUri != null && pendingEncrypt) {
                    encryptFile(pendingSourceUri, uri);
                    Toast.makeText(this, getString(R.string.encrypted_file), Toast.LENGTH_SHORT).show();
                }
                pendingSourceUri = null;
                pendingEncrypt = false;

            } else if (requestCode == REQUEST_DECRYPT_FILE) {
                if (runtimePrivateKey == null) {
                    Toast.makeText(this, getString(R.string.private_key_not_unlocked), Toast.LENGTH_SHORT).show();
                    return;
                }
                pendingSourceUri = uri;
                pendingEncrypt = false;

                String originalName = getFileName(this, uri);
                String decryptedName;
                if (originalName.endsWith(".enc")) {
                    decryptedName = originalName.substring(0, originalName.length() - 4);
                } else {
                    decryptedName = "decrypted_" + originalName;
                }

                Intent createIntent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                createIntent.addCategory(Intent.CATEGORY_OPENABLE);
                createIntent.setType("application/octet-stream");
                createIntent.putExtra(Intent.EXTRA_TITLE, decryptedName);
                startActivityForResult(createIntent, REQUEST_DECRYPT_FILE + 100);

            } else if (requestCode == REQUEST_DECRYPT_FILE + 100) {
                if (pendingSourceUri != null && !pendingEncrypt) {
                    decryptFile(pendingSourceUri, uri);
                    Toast.makeText(this, getString(R.string.decrypted_file), Toast.LENGTH_SHORT).show();
                }
                pendingSourceUri = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Operation failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private String getFileName(Context context, Uri uri) {
        String result = null;
        if ("content".equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (index != -1) {
                        result = cursor.getString(index);
                    }
                }
            }
        }
        if (result == null) {
            result = uri.getLastPathSegment();
        }
        return result;
    }

    private void encryptFile(Uri sourceUri, Uri destUri) throws Exception {
        byte[] aesKeyBytes = new byte[32]; // 256-bit AES key
        new SecureRandom().nextBytes(aesKeyBytes);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, selectedPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKeyBytes);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);

        try (InputStream in = getContentResolver().openInputStream(sourceUri);
             OutputStream out = getContentResolver().openOutputStream(destUri)) {

            out.write(encryptedAesKey.length >> 8);
            out.write(encryptedAesKey.length);
            out.write(encryptedAesKey);

            out.write(ivBytes);

            byte[] buffer = new byte[4096];
            int len;
            while ((len = in.read(buffer)) != -1) {
                byte[] encryptedData = aesCipher.update(buffer, 0, len);
                if (encryptedData != null) {
                    out.write(encryptedData);
                }
            }

            byte[] finalData = aesCipher.doFinal();
            if (finalData != null) {
                out.write(finalData);
            }
        }
    }

    private void decryptFile(Uri sourceUri, Uri destUri) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(sourceUri);
             OutputStream out = getContentResolver().openOutputStream(destUri)) {

            int keyLength = ((in.read() & 0xFF) << 8) | (in.read() & 0xFF);

            byte[] encryptedAesKey = new byte[keyLength];
            in.read(encryptedAesKey);

            byte[] ivBytes = new byte[16];
            in.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, runtimePrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

            byte[] buffer = new byte[4096];
            int len;
            while ((len = in.read(buffer)) != -1) {
                byte[] decryptedData = aesCipher.update(buffer, 0, len);
                if (decryptedData != null) {
                    out.write(decryptedData);
                }
            }

            byte[] finalData = aesCipher.doFinal();
            if (finalData != null) {
                out.write(finalData);
            }
        }
    }

    private void initializeKeys() {
        if (prefs.contains("myPublicKey") && prefs.contains("encryptedPrivateKey")) {
            try {
                String pubKeyBase64 = prefs.getString("myPublicKey", "");
                byte[] pubKeyBytes = Base64.decode(pubKeyBase64, Base64.DEFAULT);
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey publicKey = kf.generatePublic(pubSpec);
                keyPair = new KeyPair(publicKey, null);
            } catch (Exception e) {
                e.printStackTrace();
                generateRSAKeyPair();
            }
        } else {
            generateRSAKeyPair();
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

        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String password = passwordInput.getText().toString();
            if (password.isEmpty()) {
                Toast.makeText(this, R.string.generate_rsa_key_pair_builder_toast_1, Toast.LENGTH_SHORT).show();
                return;
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

                dialog.dismiss();
            } catch (Exception e) {
                e.printStackTrace();
                Toast.makeText(this, R.string.generate_rsa_key_pair_builder_toast_2 + " " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
    }

    private void encryptAndStorePrivateKey(PrivateKey privateKey, String password) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey aesKey = new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());

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
                        promptForPasswordToDecrypt();
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

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey aesKey = new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedPrivateKey);

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

            byte[] aesKeyBytes = new byte[32];
            new SecureRandom().nextBytes(aesKeyBytes);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, selectedPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKeyBytes);

            String encryptedText = Base64.encodeToString(encryptedAesKey, Base64.DEFAULT) + ":" +
                    Base64.encodeToString(ivBytes, Base64.DEFAULT) + ":" +
                    Base64.encodeToString(encryptedMessage, Base64.DEFAULT);

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

            byte[] encryptedAesKey = Base64.decode(parts[0], Base64.DEFAULT);
            byte[] ivBytes = Base64.decode(parts[1], Base64.DEFAULT);
            byte[] encryptedMessage = Base64.decode(parts[2], Base64.DEFAULT);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, runtimePrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

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

    private void signMessage() {
        if (runtimePrivateKey == null) {
            Toast.makeText(this, getString(R.string.private_key_not_unlocked), Toast.LENGTH_SHORT).show();
            if (prefs.contains("encryptedPrivateKey")) {
                promptForPasswordToDecrypt();
            }
            return;
        }

        String message = messageEditText.getText().toString();
        if (message.isEmpty()) {
            Toast.makeText(this, getString(R.string.enter_message_to_sign), Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = digest.digest(message.getBytes("UTF-8"));

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, runtimePrivateKey);
            byte[] signature = rsaCipher.doFinal(messageHash);

            String signatureBase64 = Base64.encodeToString(signature, Base64.DEFAULT);

            String result = "-----BEGIN RSA-AES256 SIGNED MESSAGE-----\n\n" +
                    message + "\n\n" +
                    "-----END RSA-AES256 SIGNED MESSAGE-----\n\n" +
                    "-----BEGIN RSA-AES256 SIGNATURE-----\n\n" +
                    signatureBase64 + "\n\n" +
                    "-----END RSA-AES256 SIGNATURE-----";

            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(result);
            Toast.makeText(this, getString(R.string.signed_message_copied), Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, getString(R.string.signing_failed), Toast.LENGTH_LONG).show();
        }
    }

    private void verifyMessage() {
        if (selectedPublicKey == null) {
            Toast.makeText(this, getString(R.string.select_contact_first), Toast.LENGTH_SHORT).show();
            return;
        }

        String fullInput = messageEditText.getText().toString().trim();
        if (fullInput.isEmpty()) {
            Toast.makeText(this, getString(R.string.paste_signed_message), Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            String beginSigned = "-----BEGIN RSA-AES256 SIGNED MESSAGE-----";
            String endSigned = "-----END RSA-AES256 SIGNED MESSAGE-----";
            int beginIdx = fullInput.indexOf(beginSigned);
            int endIdx = fullInput.indexOf(endSigned);
            if (beginIdx == -1 || endIdx == -1 || endIdx <= beginIdx) {
                Toast.makeText(this, getString(R.string.invalid_format_rsa_aes256), Toast.LENGTH_SHORT).show();
                return;
            }
            int messageStart = beginIdx + beginSigned.length() + 2;
            int messageEnd = endIdx - 2;
            String message = fullInput.substring(messageStart, messageEnd).trim();

            String beginSig = "-----BEGIN RSA-AES256 SIGNATURE-----";
            String endSig = "-----END RSA-AES256 SIGNATURE-----";
            beginIdx = fullInput.indexOf(beginSig);
            endIdx = fullInput.indexOf(endSig);
            if (beginIdx == -1 || endIdx == -1 || endIdx <= beginIdx) {
                Toast.makeText(this, getString(R.string.signature_not_found), Toast.LENGTH_SHORT).show();
                return;
            }
            int sigStart = beginIdx + beginSig.length() + 2;
            int sigEnd = endIdx - 2;
            String signatureBase64 = fullInput.substring(sigStart, sigEnd).trim();

            if (message.isEmpty() || signatureBase64.isEmpty()) {
                Toast.makeText(this, getString(R.string.empty_message_or_signature), Toast.LENGTH_SHORT).show();
                return;
            }

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = digest.digest(message.getBytes("UTF-8"));

            byte[] signature = Base64.decode(signatureBase64, Base64.DEFAULT);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, selectedPublicKey);
            byte[] decryptedHash = rsaCipher.doFinal(signature);

            if (MessageDigest.isEqual(messageHash, decryptedHash)) {
                Toast.makeText(this, getString(R.string.valid_signature), Toast.LENGTH_LONG).show();
                messageEditText.setText(message);
            } else {
                Toast.makeText(this, getString(R.string.invalid_signature), Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, getString(R.string.verification_error), Toast.LENGTH_LONG).show();
        }
    }

    private void clearText() {
        if (messageEditText.getText().toString().trim().isEmpty()) {
            Toast.makeText(this, getString(R.string.message_field_empty), Toast.LENGTH_SHORT).show();
            return;
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(getString(R.string.clear_message_title))
                .setMessage(getString(R.string.clear_message_confirm))
                .setPositiveButton(getString(R.string.yes), (dialog, which) -> {
                    messageEditText.setText("");
                })
                .setNegativeButton(getString(R.string.no), null)
                .setCancelable(true)
                .show();
    }
}