import json
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
import secrets
import re

class PasswordManager:
    def __init__(self):
        self.master_password = None
        self.passwords = {}
        self.file_path = "passwords.json"
        self.notes = {}  # Added for storing additional details

    def generate_password(self, length=16):
        try:
            if length < 8:
                raise ValueError("Password length should be at least 8 characters")

            characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?"
            password = ''.join(secrets.choice(characters) for _ in range(length))
            return password
        except ValueError as e:
            print(f"Error: {e}")
            return None

    def encrypt_password(self, password, key):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                salt=b'salt',
                iterations=100000,
                length=32,
                backend=default_backend()
            )
            key = urlsafe_b64encode(kdf.derive(key.encode()))
            cipher = key + urlsafe_b64encode(password.encode())
            return cipher
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_password(self, cipher, key):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                salt=b'salt',
                iterations=100000,
                length=32,
                backend=default_backend()
            )
            derived_key = urlsafe_b64encode(kdf.derive(key.encode()))
            encrypted_key = cipher[:44]
            if derived_key == encrypted_key:
                decrypted_password = urlsafe_b64decode(cipher[44:]).decode()
                return decrypted_password
            else:
                return None
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def save_password(self, website, username, password):
        try:
            if not self.master_password:
                print("Please set a master password first.")
                return

            key = self.master_password.encode()
            encrypted_password = self.encrypt_password(password, key)
            self.passwords[website] = {"username": username, "password": encrypted_password}
            self.notes[website] = input("Add notes (if any): ")  # Step: Notes
            self.save_to_file()
            print("Password saved successfully.")
        except Exception as e:
            print(f"Error: {e}")

    def delete_password(self, website):
        try:
            if website in self.passwords:
                del self.passwords[website]
                del self.notes[website]
                self.save_to_file()
                print(f"Password for {website} deleted successfully.")
            else:
                print(f"No password saved for {website}.")
        except Exception as e:
            print(f"Error: {e}")

    def search_password(self, keyword):
        try:
            matching_passwords = {}
            for website, info in self.passwords.items():
                if keyword.lower() in website.lower() or keyword.lower() in info['username'].lower():
                    matching_passwords[website] = info

            if matching_passwords:
                print("Matching passwords:")
                for website, info in matching_passwords.items():
                    print(f"Website: {website}, Username: {info['username']}")
                    print(f"Notes: {self.notes.get(website, 'No notes available')}")
            else:
                print(f"No matching passwords found for '{keyword}'.")
        except Exception as e:
            print(f"Error: {e}")

    def export_passwords(self, file_path):
        try:
            with open(file_path, 'w') as file:
                json.dump(
                    {"master_password": self.master_password, "passwords": self.passwords, "notes": self.notes}, file
                )
            print(f"Passwords exported to {file_path} successfully.")
        except Exception as e:
            print(f"Error exporting passwords: {e}")

    def import_passwords(self, file_path):
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
                self.master_password = data.get("master_password")
                self.passwords = data.get("passwords", {})
                self.notes = data.get("notes", {})
            print(f"Passwords imported from {file_path} successfully.")
        except Exception as e:
            print(f"Error importing passwords: {e}")

    def generate_random_password(self):
        length = int(input("Enter password length: "))
        generated_password = self.generate_password(length)
        if generated_password:
            print(f"Generated Password: {generated_password}")

    def check_password_strength(self, password):
        try:
            if len(password) < 8:
                raise ValueError("Password is weak. It should be at least 8 characters long.")
            if not re.search(r"[a-z]", password):
                raise ValueError("Password is weak. It should contain at least one lowercase letter.")
            if not re.search(r"[A-Z]", password):
                raise ValueError("Password is weak. It should contain at least one uppercase letter.")
            if not re.search(r"\d", password):
                raise ValueError("Password is weak. It should contain at least one digit.")
            if not re.search(r"[!@#$%^&*()_-+=<>?]", password):
                raise ValueError("Password is weak. It should contain at least one special character.")
            print("Password is strong.")
        except ValueError as e:
            print(f"Error: {e}")

    def save_to_file(self):
        try:
            with open(self.file_path, 'w') as file:
                json.dump(
                    {"master_password": self.master_password, "passwords": self.passwords, "notes": self.notes}, file
                )
        except Exception as e:
            print(f"Error saving to file: {e}")

    def load_from_file(self):
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, 'r') as file:
                    data = json.load(file)
                    self.master_password = data.get("master_password")
                    self.passwords = data.get("passwords", {})
                    self.notes = data.get("notes", {})
        except Exception as e:
            print(f"Error loading from file: {e}")

    def menu(self):
        self.load_from_file()
        while True:
            print("\nPassword Manager Menu:")
            print("1. Set Master Password")
            print("2. Save Password")
            print("3. Delete Password")
            print("4. Get Password")
            print("5. Search Password")
            print("6. Generate Random Password")
            print("7. Export Passwords to File")
            print("8. Import Passwords from File")
            print("9. Check Password Strength")
            print("10. Dedicated Space and Shortcut (Chrome)")
            print("11. Biometric Authentication")
            print("12. Password Alerts")
            print("13. On-device Encryption")
            print("14. Sync Across Devices")
            print("15. Manage Saved Passwords")
            print("16. Auto Sign-in")
            print("17. Control Site-specific Options")
            print("18. Manage Multiple Accounts")
            print("19. Exit")
            choice = input("Enter your choice (1-19): ")

            if choice == '1':
                self.set_master_password()
            elif choice == '2':
                website = input("Enter website: ")
                username = input("Enter username: ")
                password = getpass("Enter password: ")
                self.save_password(website, username, password)
            elif choice == '3':
                website = input("Enter website to delete password: ")
                self.delete_password(website)
            elif choice == '4':
                website = input("Enter website: ")
                self.get_password(website)
            elif choice == '5':
                keyword = input("Enter keyword to search: ")
                self.search_password(keyword)
            elif choice == '6':
                self.generate_random_password()
            elif choice == '7':
                file_path = input("Enter file path to export passwords: ")
                self.export_passwords(file_path)
            elif choice == '8':
                file_path = input("Enter file path to import passwords: ")
                self.import_passwords(file_path)
            elif choice == '9':
                password = getpass("Enter password to check strength: ")
                self.check_password_strength(password)
            elif choice == '10':
                self.open_chrome_dedicated_space()
            elif choice == '11':
                self.enable_biometric_authentication()
            elif choice == '12':
                self.enable_password_alerts()
            elif choice == '13':
                self.enable_on_device_encryption()
            elif choice == '14':
                self.enable_sync_across_devices()
            elif choice == '15':
                self.manage_saved_passwords()
            elif choice == '16':
                self.enable_auto_sign_in()
            elif choice == '17':
                self.control_site_specific_options()
            elif choice == '18':
                self.manage_multiple_accounts()
            elif choice == '19':
                self.save_to_file()
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 19.")

    def open_chrome_dedicated_space(self):
        print("Opening dedicated space in Chrome...")
        # Add code to open a dedicated space in Chrome for managing passwords
        # This could involve launching a Chrome extension or opening a specific URL

    def enable_biometric_authentication(self):
        print("Enabling biometric authentication...")
        # Add code to enable biometric authentication, such as fingerprint or facial recognition

    def enable_password_alerts(self):
        print("Enabling password alerts...")
        # Add code to enable notifications for compromised passwords in data breaches

    def enable_on_device_encryption(self):
        print("Enabling on-device encryption...")
        # Add code to encrypt passwords locally on the device before sending to Google's servers

    def enable_sync_across_devices(self):
        print("Enabling sync across devices...")
        # Add code to synchronize passwords across devices logged into the Google account

    def manage_saved_passwords(self):
        while True:
            print("\nManage Saved Passwords:")
            print("1. Edit Password")
            print("2. Delete Password")
            print("3. Export Passwords")
            print("4. Back to Main Menu")
            sub_choice = input("Enter your choice (1-4): ")

            if sub_choice == '1':
                website = input("Enter website to edit password: ")
                self.edit_password(website)
            elif sub_choice == '2':
                website = input("Enter website to delete password: ")
                self.delete_password(website)
            elif sub_choice == '3':
                file_path = input("Enter file path to export passwords: ")
                self.export_passwords(file_path)
            elif sub_choice == '4':
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 4.")

    def edit_password(self, website):
        if website in self.passwords:
            print(f"Editing password for {website}:")
            new_username = input("Enter new username (press Enter to keep the existing one): ")
            new_password = getpass("Enter new password (press Enter to keep the existing one): ")
            if new_username:
                self.passwords[website]["username"] = new_username
            if new_password:
                key = self.master_password.encode()
                encrypted_password = self.encrypt_password(new_password, key)
                self.passwords[website]["password"] = encrypted_password
            self.save_to_file()
            print("Password edited successfully.")
        else:
            print(f"No password saved for {website}.")

    def enable_auto_sign_in(self):
        print("Enabling auto sign-in...")
        # Add code to allow automatic sign-in to websites and apps using saved details

    def control_site_specific_options(self):
        print("Controlling site-specific options...")
        # Add code to manage whether to save passwords for specific websites or apps

    def manage_multiple_accounts(self):
        print("Managing multiple accounts...")
        # Add code to navigate and manage multiple Google accounts and their associated passwords

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.menu()
