# ------------------------------------------------------------
# RWB Export or Create – Version 1.5
#
# This utility is part of the RWB Password Manager project.
#
# The software is developed through a collaboration between
# Robert William Blennerhed and ChatGPT.
#
# Robert designs the concept, workflow, user interface ideas
# and practical functionality, while the programming logic
# and technical implementation are developed together with
# ChatGPT.
#
# The goal of the RWB Tech Lab projects is to create simple,
# transparent and secure local software where the user has
# full control over their own data.
#
# This tool allows:
#   • exporting encrypted vault data to CSV
#   • recreating vault.dat from CSV data
#
# It acts as a companion maintenance tool for
# RWB Password Manager.
# ------------------------------------------------------------

import base64
import csv
import json
import os
from getpass import getpass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VAULT_FILE = "vault.dat"
CSV_FILE = "vault_export.csv"

CSV_FIELDS = ["title", "username", "password", "pin", "email", "website", "note"]

DEFAULT_META = {
    "password_length": 16,
    "use_lower": True,
    "use_upper": True,
    "use_digits": True,
    "use_symbols": True,
}

MAX_TITLE_LENGTH = 100
MAX_USERNAME_LENGTH = 150
MAX_PASSWORD_LENGTH = 500
MAX_PIN_LENGTH = 8
MAX_EMAIL_LENGTH = 200
MAX_WEBSITE_LENGTH = 300
MAX_NOTE_LENGTH = 5000


class VaultManager:
    def __init__(self, filepath=VAULT_FILE):
        self.filepath = filepath
        self.data = {
            "meta": dict(DEFAULT_META),
            "entries": []
        }

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    def validate_entry_dict(self, entry: dict):
        if not isinstance(entry, dict):
            raise ValueError("Entry must be a dictionary.")

        for field in CSV_FIELDS:
            if field not in entry:
                raise ValueError(f"Missing field: {field}")
            if not isinstance(entry[field], str):
                raise ValueError(f"Field '{field}' must be text.")

        title = entry["title"].strip()
        if not title:
            raise ValueError("Title is required.")

        if len(title) > MAX_TITLE_LENGTH:
            raise ValueError(f"Title too long (max {MAX_TITLE_LENGTH}).")
        if len(entry["username"]) > MAX_USERNAME_LENGTH:
            raise ValueError(f"Username too long (max {MAX_USERNAME_LENGTH}).")
        if len(entry["password"]) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password too long (max {MAX_PASSWORD_LENGTH}).")
        if len(entry["pin"]) > MAX_PIN_LENGTH:
            raise ValueError(f"PIN too long (max {MAX_PIN_LENGTH}).")
        if entry["pin"] and not entry["pin"].isdigit():
            raise ValueError("PIN must contain digits only.")
        if len(entry["email"]) > MAX_EMAIL_LENGTH:
            raise ValueError(f"Email too long (max {MAX_EMAIL_LENGTH}).")
        if len(entry["website"]) > MAX_WEBSITE_LENGTH:
            raise ValueError(f"Website too long (max {MAX_WEBSITE_LENGTH}).")
        if len(entry["note"]) > MAX_NOTE_LENGTH:
            raise ValueError(f"Note too long (max {MAX_NOTE_LENGTH}).")

    def validate_data(self, data: dict):
        if not isinstance(data, dict):
            raise ValueError("Vault data must be a dictionary.")

        if "meta" not in data or "entries" not in data:
            raise ValueError("Vault data must contain 'meta' and 'entries'.")

        if not isinstance(data["meta"], dict):
            raise ValueError("Meta must be a dictionary.")

        if not isinstance(data["entries"], list):
            raise ValueError("Entries must be a list.")

        meta = data["meta"]
        required_meta = {
            "password_length": int,
            "use_lower": bool,
            "use_upper": bool,
            "use_digits": bool,
            "use_symbols": bool,
        }

        for key, expected_type in required_meta.items():
            if key not in meta:
                raise ValueError(f"Missing meta field: {key}")
            if not isinstance(meta[key], expected_type):
                raise ValueError(f"Invalid meta type for: {key}")

        if meta["password_length"] < 4:
            raise ValueError("Password length must be at least 4.")

        seen_titles = set()

        for entry in data["entries"]:
            self.validate_entry_dict(entry)
            normalized = entry["title"].strip().lower()
            if normalized in seen_titles:
                raise ValueError(f"Duplicate title found: {entry['title']}")
            seen_titles.add(normalized)

    def load(self, password: str):
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Vault file not found: {self.filepath}")

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as exc:
            raise ValueError("Vault file is not valid JSON.") from exc

        try:
            salt = base64.b64decode(raw["salt"])
            token = raw["token"].encode("utf-8")
        except Exception as exc:
            raise ValueError("Vault file structure is invalid.") from exc

        key = self._derive_key(password, salt)
        fernet = Fernet(key)

        try:
            decrypted = fernet.decrypt(token)
        except InvalidToken as exc:
            raise ValueError("Wrong master password or corrupted vault.") from exc

        try:
            data = json.loads(decrypted.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Decrypted vault content is invalid JSON.") from exc

        self.validate_data(data)
        self.data = data

    def save(self, password: str):
        self.validate_data(self.data)

        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        fernet = Fernet(key)

        token = fernet.encrypt(
            json.dumps(self.data, ensure_ascii=False).encode("utf-8")
        )

        raw = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "token": token.decode("utf-8"),
        }

        temp_path = self.filepath + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)

        os.replace(temp_path, self.filepath)


def input_nonempty(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Value cannot be empty.")


def export_to_csv():
    print("\n--- Export vault.dat to CSV ---")
    vault_path = input(f"Vault file [{VAULT_FILE}]: ").strip() or VAULT_FILE
    csv_path = input(f"CSV output [{CSV_FILE}]: ").strip() or CSV_FILE
    password = getpass("Master password: ")

    vault = VaultManager(vault_path)

    try:
        vault.load(password)
    except Exception as exc:
        print(f"\nERROR: {exc}\n")
        return

    entries = vault.data.get("entries", [])

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for entry in entries:
                row = {field: entry.get(field, "") for field in CSV_FIELDS}
                writer.writerow(row)
    except Exception as exc:
        print(f"\nERROR writing CSV: {exc}\n")
        return

    print(f"\nExport complete: {csv_path}")
    print("WARNING: CSV is unencrypted. Store it carefully.\n")


def create_vault_from_csv():
    print("\n--- Create vault.dat from CSV ---")
    csv_path = input(f"CSV input [{CSV_FILE}]: ").strip() or CSV_FILE
    vault_path = input(f"Vault output [{VAULT_FILE}]: ").strip() or VAULT_FILE

    if not os.path.exists(csv_path):
        print(f"\nERROR: CSV file not found: {csv_path}\n")
        return

    password1 = getpass("New master password: ")
    if not password1:
        print("\nERROR: Master password cannot be empty.\n")
        return

    password2 = getpass("Repeat master password: ")
    if password1 != password2:
        print("\nERROR: Passwords do not match.\n")
        return

    entries = []

    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames is None:
                raise ValueError("CSV file has no header row.")

            missing = [field for field in CSV_FIELDS if field not in reader.fieldnames]
            if missing:
                raise ValueError(f"CSV is missing columns: {', '.join(missing)}")

            for row_number, row in enumerate(reader, start=2):
                entry = {}
                for field in CSV_FIELDS:
                    value = row.get(field, "")
                    if value is None:
                        value = ""
                    entry[field] = str(value).strip() if field != "password" else str(value)

                try:
                    VaultManager().validate_entry_dict(entry)
                except ValueError as exc:
                    raise ValueError(f"Row {row_number}: {exc}") from exc

                entries.append(entry)

    except Exception as exc:
        print(f"\nERROR reading CSV: {exc}\n")
        return

    vault = VaultManager(vault_path)
    vault.data = {
        "meta": dict(DEFAULT_META),
        "entries": entries
    }

    try:
        vault.save(password1)
    except Exception as exc:
        print(f"\nERROR creating vault: {exc}\n")
        return

    print(f"\nVault created successfully: {vault_path}\n")


def show_menu():
    print("===================================")
    print("      RWB Export or Create")
    print("===================================")
    print("1. Export to CSV")
    print("2. Create vault.dat")
    print("3. Exit")
    print("===================================")


def main():
    while True:
        show_menu()
        choice = input("Choice: ").strip()

        if choice == "1":
            export_to_csv()
        elif choice == "2":
            create_vault_from_csv()
        elif choice == "3":
            print("\nGoodbye.\n")
            break
        else:
            print("\nInvalid choice.\n")


if __name__ == "__main__":
    main()