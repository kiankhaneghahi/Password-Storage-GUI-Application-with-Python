# Secure Python Password Manager

A desktop GUI application built with Python and Tkinter for securely storing and managing your ID/password pairs. All sensitive information is encrypted locally using strong cryptographic algorithms, ensuring your data remains private and under your control. A detailed breakdown of the code and its coresoponding cryptography implementation is given in the "Password Storage GUI" Folder README.md.

## Key Features

* **Strong Encryption:** Utilizes AES-256-GCM for authenticated encryption of your credential data. This mode provides both confidentiality and integrity, protecting against unauthorized access and tampering.
* **Robust Key Derivation:** The master password is used to derive the encryption key via PBKDF2WithHMAC-SHA256. This process incorporates a unique, cryptographically secure salt and a high iteration count (600,000) to defend against brute-force and dictionary attacks.
* **Master Password Protection:** A single master password, set by the user on first use, controls access to the entire vault. This master password is *never* stored directly, only its derived key (in memory when unlocked).
* **Local Storage:** Encrypted credentials, along with the necessary salt, nonce, and PBKDF2 iteration count, are stored in a local file named `pm_vault.enc`. This file is securely located in the same directory as the application script.
* **Credential Management (CRUD):**
    * Add new ID/password entries with descriptive labels.
    * View and Edit existing entries securely.
    * Delete entries from the vault.
* **Search Functionality:** Quickly find specific entries by searching through descriptions or ID/usernames.
* **Secure Password Generator:** A built-in utility to generate strong, random passwords with customizable criteria (length, inclusion of uppercase/lowercase letters, digits, and symbols).
* **Auto-Lock:** For enhanced security, the vault automatically locks after 15 minutes of inactivity. Manual locking is also available at any time.
* **Clipboard Management:** Conveniently copy usernames or passwords to the clipboard. A best-effort attempt is made to clear the copied data from Tkinter's clipboard view after 30 seconds.
* **User-Friendly GUI:** An intuitive graphical interface built with Python's standard Tkinter library and ttk themed widgets, aiming for a clean and modern look across different operating systems and at the same time utilized for its simplicity in implementation.
* **Atomic Saves:** Vault data is saved to a temporary file first, then renamed, to minimize the risk of data corruption if the application closes unexpectedly during a save operation.

## How it Works (High-Level)

1.  **First Use (Setup):** When the application is run for the first time (or if `pm_vault.enc` is not found), the user is prompted to create a strong master password. This password, combined with a newly generated 16-byte random salt and 600,000 iterations of PBKDF2 (HMAC-SHA256), is used to derive a 256-bit encryption key.
2.  **Data Storage:** User credentials (description, ID/username, password) are serialized (as JSON) and then encrypted using AES-256-GCM. Each encryption operation uses the derived master key and a unique, randomly generated 12-byte nonce.
3.  **Vault File (`pm_vault.enc`):** The encrypted data, along with the base64-encoded salt, nonce, and the PBKDF2 iteration count, is stored in this file. Storing these parameters ensures that the correct key can be derived for decryption.
4.  **Login:** On subsequent uses, the user enters their master password. The application reads the salt and iteration count from `pm_vault.enc`, re-derives the encryption key, and attempts to decrypt the stored data using the stored nonce. The GCM authentication tag ensures that if the password is incorrect or the data is tampered with, decryption will fail.
5.  **Security Measures:**
    * The master password itself is never stored.
    * AES-GCM provides both confidentiality (encryption) and integrity/authenticity (protection against tampering via an authentication tag).
    * PBKDF2 with a high iteration count and a unique salt makes brute-forcing the master password computationally infeasible.
    * Sensitive data like the derived master key and decrypted credentials are cleared from memory when the vault is locked or the application is closed.

## Technology Stack

* **Python 3**
* **Tkinter (with `tkinter.ttk` for themed widgets):** For the graphical user interface.
* **`cryptography` library (Python Cryptographic Authority):** For AES-GCM encryption, PBKDF2 key derivation, and secure random number generation.

## How to Run

1.  **Prerequisites:**
    * Ensure you have Python 3 installed on your system (version 3.7+ recommended).
    * The application requires the `cryptography` Python library.

2.  **Download/Clone:**
    * Download the `PasswordStorageGUI.py` script or clone this repository to your local machine.

3.  **Install Dependencies:**
    * Open your terminal or command prompt.
    * Navigate to the directory where you saved/cloned `PasswordStorageGUI.py`.
    * Install the `cryptography` library by running:
        ```bash
        pip install cryptography
        ```

4.  **Run the Application:**
    * In the terminal, while in the same directory as the script, execute:
        ```bash
        python PasswordStorageGUI.py
        ```

5.  **First-Time Setup:**
    * If it's your first time running the application, or if the `pm_vault.enc` file is not present in the script's directory, you will be guided through creating a new master password. **Choose a strong, unique, and memorable password, as this is the key to your vault and cannot be recovered if lost.**

6.  **Using the Vault:**
    * After setup or successful login, you can use the interface to add, view, edit, delete, and search for your password entries. Use the "Password Generator" for creating new, strong passwords.

**Important Note on the Vault File:**
The encrypted vault file, `pm_vault.enc`, is crucial. It is stored in the **same directory as the `PasswordStorageGUI.py` script**.
* **Backup:** It is highly recommended to back up this `pm_vault.enc` file regularly to a secure, separate location (e.g., an encrypted USB drive).
* **Resetting:** To reset the application (e.g., to set a new master password from scratch if you've forgotten the old one and are willing to lose existing data, or for testing), close the application completely and then delete the `pm_vault.enc` file. The next time you run the script, it will start with the setup process.

## Screenshots
<img width="1183" alt="Screenshot 2025-05-28 at 1 37 55 PM" src="https://github.com/user-attachments/assets/3bf44cf1-ae23-46ff-8d03-14429c45d4ac" />
<img width="1182" alt="Screenshot 2025-05-28 at 1 41 23 PM" src="https://github.com/user-attachments/assets/1c8cf08f-55f0-4d20-8d5c-6f8e1e37fef7" />
<img width="1177" alt="Screenshot 2025-05-28 at 1 42 54 PM" src="https://github.com/user-attachments/assets/909ffacb-20c4-4334-a040-ff4e07fa8eb9" />




