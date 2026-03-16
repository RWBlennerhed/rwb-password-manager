# ============================================================
# Project: RWB Password Manager
# Version: 1.5
# Year: 2026
#
# Author:
#   Robert William Blennerhed
#
# Collaboration:
#   Developed together with ChatGPT
#
# Roles:
#   Concept, design, workflow and feature ideas:
#       Robert William Blennerhed
#
#   Programming assistance and technical implementation:
#       ChatGPT
#
# Project philosophy:
#   Simple, secure and fully local software.
#   No cloud services, no tracking, no subscriptions.
#   The user owns the data.
#
# Technology:
#   Python
#   Kivy GUI
#   Fernet encryption
#
# Part of:
#   RWB Tech Lab
# ============================================================

import base64
import json
import os
import random
import shutil
import string
from datetime import datetime
from dataclasses import dataclass, asdict

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.lang import Builder
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, ObjectProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.recycleview import RecycleView
from kivy.uix.screenmanager import ScreenManager, Screen


APP_NAME = "RWB Password Manager"
APP_VERSION = "1.5"
APP_YEAR = "2026"

MAX_TITLE_LENGTH = 100
MAX_USERNAME_LENGTH = 150
MAX_PASSWORD_LENGTH = 500
MAX_PIN_LENGTH = 8
MAX_EMAIL_LENGTH = 200
MAX_WEBSITE_LENGTH = 300
MAX_NOTE_LENGTH = 5000


KV = r"""
#:import dp kivy.metrics.dp

<TitleListView>:
    viewclass: "TitleRow"
    RecycleBoxLayout:
        default_size: None, dp(44)
        default_size_hint: 1, None
        size_hint_y: None
        height: self.minimum_height
        orientation: "vertical"

<TitleRow@Button>:
    text: root.text if hasattr(root, "text") else ""
    size_hint_y: None
    height: dp(44)
    halign: "left"
    valign: "middle"
    text_size: self.width - dp(20), None
    on_release: app.open_entry(self.text)

<UnlockScreen>:
    name: "unlock"
    BoxLayout:
        orientation: "vertical"
        padding: dp(20)
        spacing: dp(12)

        Widget:
            size_hint_y: 0.15

        Label:
            text: "Password Manager"
            font_size: "24sp"
            bold: True
            size_hint_y: None
            height: dp(40)

        Label:
            text: "Master Password"
            size_hint_y: None
            height: dp(24)

        TextInput:
            id: master_password
            password: True
            multiline: False
            hint_text: "Enter master password"
            size_hint_y: None
            height: dp(44)
            write_tab: False
            on_text_validate: app.unlock_vault(self.text)

        Label:
            id: unlock_status
            text: ""
            color: 1, 0.3, 0.3, 1
            size_hint_y: None
            height: dp(24)

        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(12)

            Button:
                text: "Open / Create Vault"
                on_release: app.unlock_vault(master_password.text)

            Button:
                text: "Exit"
                on_release: app.stop()

        Widget:
            size_hint_y: 0.35

<MainScreen>:
    name: "main"
    BoxLayout:
        orientation: "vertical"
        padding: dp(10)
        spacing: dp(10)

        Label:
            id: selected_title
            text: "No entry selected"
            size_hint_y: None
            height: dp(28)
            bold: True
            text_size: self.width, None
            halign: "left"
            valign: "middle"

        TextInput:
            id: search_input
            multiline: False
            hint_text: "Search title..."
            size_hint_y: None
            height: dp(40)
            write_tab: False
            on_text: app.filter_titles(self.text)

        BoxLayout:
            orientation: "vertical"
            spacing: dp(8)
            size_hint_y: 0.50

            Label:
                text: "Titles"
                size_hint_y: None
                height: dp(24)

            TitleListView:
                id: title_list

        GridLayout:
            cols: 2
            spacing: dp(8)
            size_hint_y: None
            height: self.minimum_height

            Button:
                text: "About"
                size_hint_y: None
                height: dp(44)
                on_release: app.show_about()

            Button:
                text: "Create Data"
                size_hint_y: None
                height: dp(44)
                on_release: app.new_entry()

            Button:
                text: "Search Data"
                size_hint_y: None
                height: dp(44)
                on_release: app.focus_search()

            Button:
                text: "Password Policy"
                size_hint_y: None
                height: dp(44)
                on_release: app.show_policy_editor()

            Button:
                text: "Backup Vault"
                size_hint_y: None
                height: dp(44)
                on_release: app.create_backup()

            Button:
                text: "Statistics"
                size_hint_y: None
                height: dp(44)
                on_release: app.show_statistics()

            Button:
                text: "Delete Data"
                size_hint_y: None
                height: dp(44)
                on_release: app.delete_selected()

            Button:
                text: "Exit"
                size_hint_y: None
                height: dp(44)
                on_release: app.stop()

<EntryEditor>:
    orientation: "vertical"
    spacing: dp(8)
    padding: dp(12)

    ScrollView:
        do_scroll_x: False

        GridLayout:
            cols: 1
            spacing: dp(8)
            size_hint_y: None
            height: self.minimum_height

            TextInput:
                id: title
                hint_text: "Title *"
                multiline: False
                text: root.title_text
                size_hint_y: None
                height: dp(44)

            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)

                TextInput:
                    id: username
                    hint_text: "Username"
                    multiline: False
                    text: root.username_text

                Button:
                    text: "CP"
                    size_hint_x: None
                    width: dp(50)
                    on_release: root.copy_field("username")

            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)

                TextInput:
                    id: password
                    hint_text: "Password"
                    multiline: False
                    password: True
                    text: root.password_text

                Button:
                    text: "CP"
                    size_hint_x: None
                    width: dp(50)
                    on_release: root.copy_field("password")

            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)

                TextInput:
                    id: pin
                    hint_text: "PIN"
                    multiline: False
                    input_filter: "int"
                    text: root.pin_text

                Button:
                    text: "CP"
                    size_hint_x: None
                    width: dp(50)
                    on_release: root.copy_field("pin")

            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)

                TextInput:
                    id: email
                    hint_text: "Email"
                    multiline: False
                    text: root.email_text

                Button:
                    text: "CP"
                    size_hint_x: None
                    width: dp(50)
                    on_release: root.copy_field("email")

            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)

                TextInput:
                    id: website
                    hint_text: "Website"
                    multiline: False
                    text: root.website_text

                Button:
                    text: "CP"
                    size_hint_x: None
                    width: dp(50)
                    on_release: root.copy_field("website")

            TextInput:
                id: note
                hint_text: "Note"
                text: root.note_text
                size_hint_y: None
                height: dp(140)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(8)

        Button:
            id: toggle_btn
            text: "Show Password"
            on_release: root.toggle_password()

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(8)

        Button:
            text: "Generate"
            on_release: root.generate_password()

        Button:
            text: "Cancel"
            on_release: root.cancel()

        Button:
            text: "Save"
            on_release: root.save()

<PolicyEditor>:
    orientation: "vertical"
    spacing: dp(10)
    padding: dp(12)

    Label:
        text: "Password Length"
        size_hint_y: None
        height: dp(24)

    TextInput:
        id: length_input
        text: str(root.password_length)
        multiline: False
        input_filter: "int"
        size_hint_y: None
        height: dp(44)

    BoxLayout:
        size_hint_y: None
        height: dp(36)
        spacing: dp(8)

        CheckBox:
            id: lower_cb
            active: root.use_lower
            size_hint_x: None
            width: dp(40)
        Label:
            text: "Lowercase letters"
            text_size: self.width, None
            halign: "left"
            valign: "middle"

    BoxLayout:
        size_hint_y: None
        height: dp(36)
        spacing: dp(8)

        CheckBox:
            id: upper_cb
            active: root.use_upper
            size_hint_x: None
            width: dp(40)
        Label:
            text: "Uppercase letters"
            text_size: self.width, None
            halign: "left"
            valign: "middle"

    BoxLayout:
        size_hint_y: None
        height: dp(36)
        spacing: dp(8)

        CheckBox:
            id: digits_cb
            active: root.use_digits
            size_hint_x: None
            width: dp(40)
        Label:
            text: "Digits"
            text_size: self.width, None
            halign: "left"
            valign: "middle"

    BoxLayout:
        size_hint_y: None
        height: dp(36)
        spacing: dp(8)

        CheckBox:
            id: symbols_cb
            active: root.use_symbols
            size_hint_x: None
            width: dp(40)
        Label:
            text: "Symbols"
            text_size: self.width, None
            halign: "left"
            valign: "middle"

    Widget:

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(8)

        Button:
            text: "Cancel"
            on_release: root.cancel()

        Button:
            text: "Save"
            on_release: root.save()
"""


@dataclass
class EntryData:
    title: str
    username: str = ""
    password: str = ""
    pin: str = ""
    email: str = ""
    website: str = ""
    note: str = ""


class VaultManager:
    def __init__(self, filepath="vault.dat"):
        self.filepath = filepath
        self.data = self.default_data()

    def default_data(self):
        return {
            "meta": {
                "password_length": 16,
                "use_lower": True,
                "use_upper": True,
                "use_digits": True,
                "use_symbols": True,
            },
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

    def exists(self) -> bool:
        return os.path.exists(self.filepath)

    def validate_data(self, data):
        if not isinstance(data, dict):
            raise ValueError("Vault data must be a dictionary.")

        if "meta" not in data or "entries" not in data:
            raise ValueError("Vault data is missing required sections.")

        meta = data["meta"]
        entries = data["entries"]

        if not isinstance(meta, dict):
            raise ValueError("Vault meta section must be a dictionary.")

        if not isinstance(entries, list):
            raise ValueError("Vault entries section must be a list.")

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
                raise ValueError(f"Invalid type for meta field: {key}")

        if meta["password_length"] < 4:
            raise ValueError("Password length must be at least 4.")

        seen_titles = set()

        required_fields = ["title", "username", "password", "pin", "email", "website", "note"]

        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"Entry {i} is not a dictionary.")

            for field in required_fields:
                if field not in entry:
                    raise ValueError(f"Entry {i} is missing field: {field}")
                if not isinstance(entry[field], str):
                    raise ValueError(f"Entry {i} field '{field}' must be text.")

            title = entry["title"].strip()
            if not title:
                raise ValueError(f"Entry {i} has an empty title.")

            if len(title) > MAX_TITLE_LENGTH:
                raise ValueError(f"Entry {i} title is too long.")

            if len(entry["username"]) > MAX_USERNAME_LENGTH:
                raise ValueError(f"Entry {i} username is too long.")

            if len(entry["password"]) > MAX_PASSWORD_LENGTH:
                raise ValueError(f"Entry {i} password is too long.")

            if len(entry["pin"]) > MAX_PIN_LENGTH:
                raise ValueError(f"Entry {i} PIN is too long.")

            if len(entry["email"]) > MAX_EMAIL_LENGTH:
                raise ValueError(f"Entry {i} email is too long.")

            if len(entry["website"]) > MAX_WEBSITE_LENGTH:
                raise ValueError(f"Entry {i} website is too long.")

            if len(entry["note"]) > MAX_NOTE_LENGTH:
                raise ValueError(f"Entry {i} note is too long.")

            normalized_title = title.lower()
            if normalized_title in seen_titles:
                raise ValueError(f"Duplicate title detected: {title}")
            seen_titles.add(normalized_title)

    def load_or_create(self, password: str):
        if not self.exists():
            self.data = self.default_data()
            self.save(password)
            return

        try:
            with open(self.filepath, "rb") as f:
                raw = json.loads(f.read().decode("utf-8"))
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
            loaded_data = json.loads(decrypted.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Decrypted vault content is invalid JSON.") from exc

        self.validate_data(loaded_data)
        self.data = loaded_data

    def save(self, password: str):
        self.validate_data(self.data)

        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        token = fernet.encrypt(json.dumps(self.data, ensure_ascii=False).encode("utf-8"))

        raw = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "token": token.decode("utf-8"),
        }

        temp_path = self.filepath + ".tmp"
        with open(temp_path, "wb") as f:
            f.write(json.dumps(raw, ensure_ascii=False, indent=2).encode("utf-8"))

        os.replace(temp_path, self.filepath)

    def titles(self):
        return sorted([e["title"] for e in self.data["entries"]], key=str.lower)

    def find_entry(self, title: str):
        for item in self.data["entries"]:
            if item["title"] == title:
                return item
        return None

    def find_entry_casefold(self, title: str):
        target = title.strip().lower()
        for item in self.data["entries"]:
            if item["title"].strip().lower() == target:
                return item
        return None

    def upsert_entry(self, entry: EntryData):
        self.validate_entry(entry)

        old = self.find_entry(entry.title)
        if old:
            old.update(asdict(entry))
        else:
            self.data["entries"].append(asdict(entry))

        self.validate_data(self.data)

    def delete_entry(self, title: str):
        self.data["entries"] = [e for e in self.data["entries"] if e["title"] != title]
        self.validate_data(self.data)

    def validate_entry(self, entry: EntryData):
        if not isinstance(entry, EntryData):
            raise ValueError("Invalid entry object.")

        title = entry.title.strip()
        if not title:
            raise ValueError("Title is required.")

        if len(title) > MAX_TITLE_LENGTH:
            raise ValueError(f"Title is too long. Max {MAX_TITLE_LENGTH} characters.")

        if len(entry.username) > MAX_USERNAME_LENGTH:
            raise ValueError(f"Username is too long. Max {MAX_USERNAME_LENGTH} characters.")

        if len(entry.password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password is too long. Max {MAX_PASSWORD_LENGTH} characters.")

        if len(entry.pin) > MAX_PIN_LENGTH:
            raise ValueError(f"PIN is too long. Max {MAX_PIN_LENGTH} digits.")

        if entry.pin and not entry.pin.isdigit():
            raise ValueError("PIN must contain digits only.")

        if len(entry.email) > MAX_EMAIL_LENGTH:
            raise ValueError(f"Email is too long. Max {MAX_EMAIL_LENGTH} characters.")

        if len(entry.website) > MAX_WEBSITE_LENGTH:
            raise ValueError(f"Website is too long. Max {MAX_WEBSITE_LENGTH} characters.")

        if len(entry.note) > MAX_NOTE_LENGTH:
            raise ValueError(f"Note is too long. Max {MAX_NOTE_LENGTH} characters.")


class TitleListView(RecycleView):
    pass


class UnlockScreen(Screen):
    pass


class MainScreen(Screen):
    pass


class EntryEditor(BoxLayout):
    popup = ObjectProperty(None)
    original_title = StringProperty("")
    title_text = StringProperty("")
    username_text = StringProperty("")
    password_text = StringProperty("")
    pin_text = StringProperty("")
    email_text = StringProperty("")
    website_text = StringProperty("")
    note_text = StringProperty("")
    _clipboard_event = ObjectProperty(None, allownone=True)

    def load_entry(self, entry: dict):
        self.original_title = entry.get("title", "")
        self.title_text = entry.get("title", "")
        self.username_text = entry.get("username", "")
        self.password_text = entry.get("password", "")
        self.pin_text = entry.get("pin", "")
        self.email_text = entry.get("email", "")
        self.website_text = entry.get("website", "")
        self.note_text = entry.get("note", "")

    def generate_password(self):
        app = App.get_running_app()
        self.ids.password.text = app.generate_password()

    def toggle_password(self):
        field = self.ids.password
        btn = self.ids.toggle_btn
        field.password = not field.password
        btn.text = "Show Password" if field.password else "Hide Password"

    def copy_field(self, field_id):
        text = self.ids[field_id].text
        if not text:
            App.get_running_app().show_message("Nothing to copy.")
            return

        Clipboard.copy(text)

        if self._clipboard_event is not None:
            self._clipboard_event.cancel()

        self._clipboard_event = Clock.schedule_once(self.clear_clipboard, 20)
        App.get_running_app().show_message(f"Copied {field_id}.", title="Copied")

    def clear_clipboard(self, _dt):
        Clipboard.copy("")
        self._clipboard_event = None

    def cancel(self):
        if self.popup:
            self.popup.dismiss()

    def save(self):
        app = App.get_running_app()

        title = self.ids.title.text.strip()
        username = self.ids.username.text.strip()
        password = self.ids.password.text
        pin = self.ids.pin.text.strip()
        email = self.ids.email.text.strip()
        website = self.ids.website.text.strip()
        note = self.ids.note.text.strip()

        if not title:
            app.show_message("Title is required.")
            return

        if len(title) > MAX_TITLE_LENGTH:
            app.show_message(f"Title is too long. Max {MAX_TITLE_LENGTH} characters.")
            return

        if len(username) > MAX_USERNAME_LENGTH:
            app.show_message(f"Username is too long. Max {MAX_USERNAME_LENGTH} characters.")
            return

        if len(password) > MAX_PASSWORD_LENGTH:
            app.show_message(f"Password is too long. Max {MAX_PASSWORD_LENGTH} characters.")
            return

        if pin:
            if not pin.isdigit():
                app.show_message("PIN must contain digits only.")
                return
            if len(pin) > MAX_PIN_LENGTH:
                app.show_message(f"PIN is too long. Max {MAX_PIN_LENGTH} digits.")
                return

        if len(email) > MAX_EMAIL_LENGTH:
            app.show_message(f"Email is too long. Max {MAX_EMAIL_LENGTH} characters.")
            return

        if len(website) > MAX_WEBSITE_LENGTH:
            app.show_message(f"Website is too long. Max {MAX_WEBSITE_LENGTH} characters.")
            return

        if len(note) > MAX_NOTE_LENGTH:
            app.show_message(f"Note is too long. Max {MAX_NOTE_LENGTH} characters.")
            return

        existing = app.vault.find_entry_casefold(title)
        if existing:
            existing_title = existing["title"]
            if self.original_title.strip().lower() != title.lower():
                app.show_message("A title with that name already exists.")
                return
            if self.original_title != existing_title and self.original_title.strip().lower() == title.lower():
                app.show_message("A title with that name already exists.")
                return

        if self.original_title and self.original_title != title:
            app.vault.delete_entry(self.original_title)

        entry = EntryData(
            title=title,
            username=username,
            password=password,
            pin=pin,
            email=email,
            website=website,
            note=note,
        )

        try:
            app.vault.upsert_entry(entry)
            app.vault.save(app.master_password)
        except ValueError as exc:
            app.show_message(str(exc), title="Validation Error")
            return
        except Exception as exc:
            app.show_message(f"Could not save entry:\n{exc}", title="Save Error")
            return

        app.selected_title = title
        app.refresh_titles()

        if self.popup:
            self.popup.dismiss()


class PolicyEditor(BoxLayout):
    popup = ObjectProperty(None)
    password_length = NumericProperty(16)
    use_lower = BooleanProperty(True)
    use_upper = BooleanProperty(True)
    use_digits = BooleanProperty(True)
    use_symbols = BooleanProperty(True)

    def load_policy(self, meta: dict):
        self.password_length = int(meta.get("password_length", 16))
        self.use_lower = bool(meta.get("use_lower", True))
        self.use_upper = bool(meta.get("use_upper", True))
        self.use_digits = bool(meta.get("use_digits", True))
        self.use_symbols = bool(meta.get("use_symbols", True))

    def cancel(self):
        if self.popup:
            self.popup.dismiss()

    def save(self):
        app = App.get_running_app()

        raw_length = self.ids.length_input.text.strip()
        if not raw_length:
            app.show_message("Password length is required.")
            return

        try:
            length = int(raw_length)
        except ValueError:
            app.show_message("Password length must be a valid number.")
            return

        if length < 4:
            app.show_message("Password length must be at least 4.")
            return

        use_lower = self.ids.lower_cb.active
        use_upper = self.ids.upper_cb.active
        use_digits = self.ids.digits_cb.active
        use_symbols = self.ids.symbols_cb.active

        if not any([use_lower, use_upper, use_digits, use_symbols]):
            app.show_message("Select at least one character type.")
            return

        app.vault.data["meta"] = {
            "password_length": length,
            "use_lower": use_lower,
            "use_upper": use_upper,
            "use_digits": use_digits,
            "use_symbols": use_symbols,
        }

        try:
            app.vault.save(app.master_password)
        except ValueError as exc:
            app.show_message(str(exc), title="Validation Error")
            return
        except Exception as exc:
            app.show_message(f"Could not save policy:\n{exc}", title="Save Error")
            return

        if self.popup:
            self.popup.dismiss()


class PasswordManagerApp(App):
    selected_title = StringProperty("")
    filtered_titles = ListProperty([])

    def build(self):
        self.title = APP_NAME
        self.vault = VaultManager()
        self.master_password = ""
        Builder.load_string(KV)

        sm = ScreenManager()
        sm.add_widget(UnlockScreen())
        sm.add_widget(MainScreen())
        return sm

    def unlock_vault(self, password: str):
        if not password:
            self.root.get_screen("unlock").ids.unlock_status.text = "Enter a master password."
            return

        try:
            self.vault.load_or_create(password)
        except ValueError as exc:
            self.root.get_screen("unlock").ids.unlock_status.text = str(exc)
            return
        except Exception:
            self.root.get_screen("unlock").ids.unlock_status.text = "Unexpected error while opening vault."
            return

        self.master_password = password
        self.root.get_screen("unlock").ids.unlock_status.text = ""
        self.refresh_titles()
        self.root.current = "main"

    def refresh_titles(self):
        titles = self.vault.titles()
        self.filtered_titles = titles

        rv = self.root.get_screen("main").ids.title_list
        rv.data = [{"text": title} for title in titles]

        label = self.root.get_screen("main").ids.selected_title
        label.text = self.selected_title if self.selected_title else "No entry selected"

    def filter_titles(self, text: str):
        text = text.strip().lower()
        titles = self.vault.titles()
        if text:
            titles = [t for t in titles if text in t.lower()]

        self.filtered_titles = titles
        self.root.get_screen("main").ids.title_list.data = [{"text": t} for t in titles]

    def focus_search(self):
        self.root.get_screen("main").ids.search_input.focus = True

    def open_entry(self, title: str):
        entry = self.vault.find_entry(title)
        if not entry:
            return

        self.selected_title = title
        self.root.get_screen("main").ids.selected_title.text = title

        editor = EntryEditor()
        editor.load_entry(entry)

        popup = Popup(
            title=f"Edit: {title}",
            content=editor,
            size_hint=(0.95, 0.95),
        )
        editor.popup = popup
        popup.open()

    def new_entry(self):
        editor = EntryEditor()
        popup = Popup(
            title="Create Data",
            content=editor,
            size_hint=(0.95, 0.95),
        )
        editor.popup = popup
        popup.open()

    def delete_selected(self):
        if not self.selected_title:
            self.show_message("No selected entry.")
            return

        from kivy.uix.button import Button
        from kivy.uix.label import Label

        content = BoxLayout(orientation="vertical", padding=12, spacing=8)
        content.add_widget(Label(text=f"Delete '{self.selected_title}'?"))

        buttons = BoxLayout(size_hint_y=None, height=44, spacing=8)
        cancel_btn = Button(text="Cancel")
        delete_btn = Button(text="Delete")
        buttons.add_widget(cancel_btn)
        buttons.add_widget(delete_btn)
        content.add_widget(buttons)

        popup = Popup(title="Confirm Delete", content=content, size_hint=(0.8, 0.35))
        cancel_btn.bind(on_release=popup.dismiss)

        def do_delete(_instance):
            try:
                self.vault.delete_entry(self.selected_title)
                self.vault.save(self.master_password)
                self.selected_title = ""
                self.refresh_titles()
                popup.dismiss()
            except Exception as exc:
                popup.dismiss()
                self.show_message(f"Could not delete entry:\n{exc}", title="Delete Error")

        delete_btn.bind(on_release=do_delete)
        popup.open()

    def show_about(self):
        text = (
            f"{APP_NAME}\n"
            f"Version {APP_VERSION} ({APP_YEAR})\n\n"
            "Simple local password manager\n\n"
            "Data is stored in one encrypted local file.\n"
            "You control the file yourself.\n\n"
            "Part of RWB Tech Lab."
        )
        self.show_message(text, title="About")

    def show_policy_editor(self):
        editor = PolicyEditor()
        editor.load_policy(self.vault.data["meta"])

        popup = Popup(
            title="Password Policy",
            content=editor,
            size_hint=(0.9, 0.7),
        )
        editor.popup = popup
        popup.open()

    def create_backup(self):
        if not self.master_password:
            self.show_message("Open the vault first.")
            return

        try:
            self.vault.save(self.master_password)

            project_dir = os.path.dirname(os.path.abspath(self.vault.filepath))
            date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            backup_name = f"Vault_{date_str}.dat"
            backup_path = os.path.join(project_dir, backup_name)

            shutil.copy2(self.vault.filepath, backup_path)

            self.show_message(
                f"Backup saved successfully:\n{backup_path}",
                title="Backup Complete"
            )
        except Exception as exc:
            self.show_message(
                f"Backup failed:\n{exc}",
                title="Backup Error"
            )

    def show_statistics(self):
        entries = self.vault.data.get("entries", [])
        total = len(entries)

        with_username = sum(1 for e in entries if e.get("username", "").strip())
        with_password = sum(1 for e in entries if e.get("password", "").strip())
        with_pin = sum(1 for e in entries if e.get("pin", "").strip())
        with_email = sum(1 for e in entries if e.get("email", "").strip())
        with_website = sum(1 for e in entries if e.get("website", "").strip())
        with_note = sum(1 for e in entries if e.get("note", "").strip())

        passwords = [e.get("password", "") for e in entries if e.get("password", "").strip()]
        password_lengths = [len(p) for p in passwords]

        avg_password_length = round(sum(password_lengths) / len(password_lengths), 2) if password_lengths else 0
        max_password_length = max(password_lengths) if password_lengths else 0
        min_password_length = min(password_lengths) if password_lengths else 0

        weak_passwords = sum(1 for p in passwords if len(p) < 8)
        medium_passwords = sum(1 for p in passwords if 8 <= len(p) < 12)
        strong_passwords = sum(1 for p in passwords if len(p) >= 12)

        titles = [e.get("title", "").strip().lower() for e in entries if e.get("title", "").strip()]
        duplicate_titles = len(titles) - len(set(titles))

        vault_size_bytes = 0
        if os.path.exists(self.vault.filepath):
            vault_size_bytes = os.path.getsize(self.vault.filepath)

        vault_size_kb = round(vault_size_bytes / 1024, 2)

        estimated_capacity = 0
        if total > 0 and vault_size_bytes > 0:
            avg_bytes_per_entry = vault_size_bytes / total
            if avg_bytes_per_entry > 0:
                estimated_capacity = int((1024 * 1024) / avg_bytes_per_entry)

        stats = f"""
Advanced Vault Statistics

Total entries: {total}

With username: {with_username}
With password: {with_password}
With PIN: {with_pin}
With email: {with_email}
With website: {with_website}
With note: {with_note}

Average password length: {avg_password_length}
Shortest password length: {min_password_length}
Longest password length: {max_password_length}

Weak passwords (<8): {weak_passwords}
Medium passwords (8-11): {medium_passwords}
Strong passwords (12+): {strong_passwords}

Duplicate titles: {duplicate_titles}

Vault file size: {vault_size_kb} KB
Estimated capacity per 1 MB: ~{estimated_capacity} entries
"""
        self.show_message(stats, title="Statistics")

    def generate_password(self) -> str:
        meta = self.vault.data["meta"]

        groups = []
        if meta["use_lower"]:
            groups.append(string.ascii_lowercase)
        if meta["use_upper"]:
            groups.append(string.ascii_uppercase)
        if meta["use_digits"]:
            groups.append(string.digits)
        if meta["use_symbols"]:
            groups.append("!@#$%^&*()-_=+[]{};:,.?")

        if not groups:
            groups = [string.ascii_letters + string.digits]

        length = max(int(meta["password_length"]), len(groups))
        rng = random.SystemRandom()

        password_chars = [rng.choice(group) for group in groups]
        all_chars = "".join(groups)

        while len(password_chars) < length:
            password_chars.append(rng.choice(all_chars))

        rng.shuffle(password_chars)
        return "".join(password_chars)

    def show_message(self, text: str, title: str = "Info"):
        from kivy.uix.button import Button
        from kivy.uix.label import Label
        from kivy.uix.scrollview import ScrollView

        content = BoxLayout(orientation="vertical", padding=12, spacing=8)

        scroll = ScrollView(do_scroll_x=False)
        label = Label(
            text=text,
            size_hint_y=None,
            halign="left",
            valign="top"
        )

        def update_label(*_args):
            label.text_size = (scroll.width - 20, None)
            label.texture_update()
            label.height = label.texture_size[1] + 20

        scroll.bind(size=update_label)
        label.bind(texture_size=update_label)

        scroll.add_widget(label)
        content.add_widget(scroll)

        btn = Button(text="OK", size_hint_y=None, height=44)
        content.add_widget(btn)

        popup = Popup(title=title, content=content, size_hint=(0.9, 0.75))
        btn.bind(on_release=popup.dismiss)
        popup.open()


if __name__ == "__main__":
    PasswordManagerApp().run()