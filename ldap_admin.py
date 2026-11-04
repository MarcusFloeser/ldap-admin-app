#!/usr/bin/env python3
"""
LDAP Admin – grafische Verwaltungsoberfläche für LDAP-Server (macOS & Linux).

Funktionen:
  * mehrere gespeicherte Verbindungsprofile (ldap://, StartTLS, ldaps://)
  * Passwörter optional im System-Schlüsselbund (macOS-Schlüsselbund, KWallet, GNOME)
  * mehrere Verbindungen gleichzeitig in Tabs
  * Verzeichnisbaum, Attribute anzeigen/bearbeiten, Einträge anlegen/löschen/umbenennen/verschieben
  * Suche mit LDAP-Filter (CSV-Export), LDIF-Export, Passwort setzen, Server-Info
  * Nur-Lesen-Modus pro Profil, Offline-Demo-Server zum Ausprobieren
"""
from __future__ import annotations

import csv
import os
import sys
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace

try:
    from PySide6.QtCore import QSettings, QSize, Qt, QTimer
    from PySide6.QtGui import QAction, QActionGroup, QColor, QCursor, QFont, QKeySequence
    from PySide6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
        QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QHeaderView, QInputDialog,
        QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox,
        QPlainTextEdit, QPushButton, QSizePolicy, QSpinBox, QSplitter, QStackedWidget, QStyle, QTabWidget,
        QTableWidget, QTableWidgetItem, QToolBar, QTreeWidget, QTreeWidgetItem,
        QTreeWidgetItemIterator, QVBoxLayout, QWidget,
    )
except ImportError:
    sys.exit("PySide6 fehlt. Bitte mit ./start.sh starten oder: pip install -r requirements.txt")

try:
    from ldap3 import BASE, LEVEL, SUBTREE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    sys.exit("ldap3 fehlt. Bitte mit ./start.sh starten oder: pip install -r requirements.txt")

from ldap_backend import (
    CHILD_LIMIT, PASSWORD_SCHEMES, LdapError, LdapSession, NonLeafMoveError, Profile,
    ProfileStore, decode_value,
    demo_session, describe_password, hash_password, is_hashed, local_scheme, norm_dn, parent_of,
    parse_ldif, rdn_of, split_dn,
)

APP_NAME = "LDAP Admin"
APP_VERSION = "1.10"
ROLE_DN = Qt.ItemDataRole.UserRole
ROLE_LOADED = Qt.ItemDataRole.UserRole + 1
ROLE_RAW = Qt.ItemDataRole.UserRole + 2
ROLE_OP = Qt.ItemDataRole.UserRole + 3
ROLE_SEP = Qt.ItemDataRole.UserRole + 4
FAIL = object()


class Raw:
    """Hält Rohbytes in Item-Daten, ohne dass Qt sie in QByteArray umwandelt."""
    __slots__ = ("b",)

    def __init__(self, b: bytes):
        self.b = b


def get_raw(item) -> bytes | None:
    data = item.data(ROLE_RAW)
    return data.b if isinstance(data, Raw) else None
EDITABLE = Qt.ItemFlag.ItemIsEditable
CONTAINER_ATTRS = {"dc", "ou", "o", "c", "l", "st", "cn=users"}


@contextmanager
def busy():
    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        yield
    finally:
        QApplication.restoreOverrideCursor()


def run_safely(parent, title, fn, *args, **kwargs):
    """Führt eine LDAP-Aktion aus und zeigt Fehler als Dialog. Gibt bei Fehler FAIL zurück."""
    try:
        with busy():
            return fn(*args, **kwargs)
    except (LdapError, LDAPException, OSError, ValueError) as exc:
        QMessageBox.critical(parent, title, str(exc) or exc.__class__.__name__)
        return FAIL


def fit_list_width(lw: QListWidget, minimum: int = 280) -> int:
    """Breite, damit der längste Eintrag vollständig sichtbar ist (max. 85 % des Bildschirms)."""
    content = lw.sizeHintForColumn(0) if lw.count() else 0
    width = content + 2 * lw.frameWidth() + lw.verticalScrollBar().sizeHint().width() + 16
    screen = lw.screen()
    limit = int(screen.availableGeometry().width() * 0.85) if screen else 1600
    return max(minimum, min(width, limit))


TOOLBAR_STYLES = [
    ("compact", "Kompakt – kleine Symbole mit Text"),
    ("icons", "Nur Symbole (Text als Tooltip)"),
    ("large", "Groß – Symbole über dem Text"),
]


def apply_toolbar_style(tb: QToolBar, mode: str) -> None:
    if mode == "icons":
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        tb.setIconSize(QSize(18, 18))
    elif mode == "large":
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
        tb.setIconSize(QSize(24, 24))
    else:
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        tb.setIconSize(QSize(16, 16))


def settings() -> QSettings:
    return QSettings("ldap-admin", "LDAP Admin")


def make_form() -> QFormLayout:
    form = QFormLayout()
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return form


class SizeMemory:
    """Mixin für Dialoge: merkt sich die vom Benutzer gewählte Fenstergröße."""

    def _size_key(self) -> str:
        return f"dialogs/{type(self).__name__}"

    def showEvent(self, event):
        if not getattr(self, "_size_restored", False):
            self._size_restored = True
            size = settings().value(self._size_key())
            try:
                w, h = (int(x) for x in str(size).split("x")) if size else (0, 0)
            except ValueError:
                w = h = 0
            if w > 0 and h > 0:
                self.resize(max(w, self.minimumSizeHint().width()),
                            max(h, self.minimumSizeHint().height()))
        super().showEvent(event)

    def done(self, result):
        try:
            settings().setValue(self._size_key(), f"{self.width()}x{self.height()}")
        except Exception:
            pass
        super().done(result)


def std_icon(widget, name):
    return widget.style().standardIcon(getattr(QStyle.StandardPixmap, name))


# =========================================================================== #
# Verbindungsprofile
# =========================================================================== #
class ConnectionDialog(SizeMemory, QDialog):
    SECURITY = [("Unverschlüsselt (ldap://)", "none"), ("StartTLS", "starttls"),
                ("SSL/TLS (ldaps://)", "ldaps")]
    AUTH = [("Benutzer + Passwort (Simple Bind)", "simple"), ("Anonym", "anonymous")]

    def __init__(self, store: ProfileStore, profile: Profile, parent=None):
        super().__init__(parent)
        self.store = store
        self.profile = profile
        self.password = ""
        self.setWindowTitle("Verbindung bearbeiten")
        self.setMinimumWidth(520)

        self.name = QLineEdit(profile.name)
        self.host = QLineEdit(profile.host)
        self.host.setPlaceholderText("ldap.firma.ch")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(profile.port))
        self.security = QComboBox()
        for label, key in self.SECURITY:
            self.security.addItem(label, key)
        self.security.setCurrentIndex([k for _, k in self.SECURITY].index(profile.security))
        self.security.currentIndexChanged.connect(self._security_changed)
        self.verify = QCheckBox("Zertifikat prüfen")
        self.verify.setChecked(profile.verify_cert)
        self.ca_file = QLineEdit(profile.ca_file)
        self.ca_file.setPlaceholderText("optional – sonst System-Zertifikate")
        ca_btn = QPushButton("…")
        ca_btn.setFixedWidth(32)
        ca_btn.clicked.connect(self._pick_ca)
        ca_row = QHBoxLayout()
        ca_row.addWidget(self.ca_file)
        ca_row.addWidget(ca_btn)

        self.auth = QComboBox()
        for label, key in self.AUTH:
            self.auth.addItem(label, key)
        self.auth.setCurrentIndex([k for _, k in self.AUTH].index(profile.auth))
        self.auth.currentIndexChanged.connect(self._auth_changed)
        self.bind_dn = QLineEdit(profile.bind_dn)
        self.bind_dn.setPlaceholderText("cn=admin,dc=firma,dc=ch  oder  user@firma.ch (AD)")
        self.pw = QLineEdit(store.get_password(profile) or "")
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.setPlaceholderText("leer lassen = beim Verbinden fragen")
        self.save_pw = QCheckBox("Passwort im Schlüsselbund speichern")
        self.save_pw.setChecked(profile.save_password)
        if not store.keyring_available():
            self.save_pw.setChecked(False)
            self.save_pw.setEnabled(False)
            self.save_pw.setToolTip("Kein Schlüsselbund verfügbar (Python-Paket 'keyring').")

        self.base_dn = QLineEdit(profile.base_dn)
        self.base_dn.setPlaceholderText("leer = vom Server ermitteln")
        detect = QPushButton("Ermitteln")
        detect.clicked.connect(self._detect_base)
        base_row = QHBoxLayout()
        base_row.addWidget(self.base_dn)
        base_row.addWidget(detect)
        self.read_only = QCheckBox("Nur lesen (keine Änderungen möglich)")
        self.read_only.setChecked(profile.read_only)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 300)
        self.timeout.setSuffix(" s")
        self.timeout.setValue(int(profile.timeout))
        self.page_size = QSpinBox()
        self.page_size.setRange(10, 10000)
        self.page_size.setValue(int(profile.page_size))
        self.pw_scheme = scheme_combo(profile.password_scheme)
        self.pw_scheme.setToolTip("Standard für neue Benutzerpasswörter in diesem Verzeichnis "
                                  "(Passwort setzen, neue Einträge, LDIF-Import).")

        form = make_form()
        form.addRow("Name:", self.name)
        form.addRow("Server:", self.host)
        form.addRow("Port:", self.port)
        form.addRow("Sicherheit:", self.security)
        form.addRow("", self.verify)
        form.addRow("CA-Zertifikat:", ca_row)
        form.addRow("Anmeldung:", self.auth)
        form.addRow("Bind-DN:", self.bind_dn)
        form.addRow("Passwort:", self.pw)
        form.addRow("", self.save_pw)
        form.addRow("Basis-DN:", base_row)
        form.addRow("Timeout:", self.timeout)
        form.addRow("Seitengröße:", self.page_size)
        form.addRow("Benutzer-Passwörter:", self.pw_scheme)
        form.addRow("", self.read_only)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        test = buttons.addButton("Verbindung testen", QDialogButtonBox.ButtonRole.ActionRole)
        test.clicked.connect(self._test)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self._security_changed(update_port=False)
        self._auth_changed()

    def _security_changed(self, *_, update_port=True):
        key = self.security.currentData()
        if update_port:
            if key == "ldaps" and self.port.value() == 389:
                self.port.setValue(636)
            elif key != "ldaps" and self.port.value() == 636:
                self.port.setValue(389)
        tls = key != "none"
        self.verify.setEnabled(tls)
        self.ca_file.setEnabled(tls)

    def _auth_changed(self, *_):
        simple = self.auth.currentData() == "simple"
        for w in (self.bind_dn, self.pw):
            w.setEnabled(simple)
        self.save_pw.setEnabled(simple and self.store.keyring_available())

    def _pick_ca(self):
        path, _ = QFileDialog.getOpenFileName(self, "CA-Zertifikat wählen", "",
                                              "Zertifikate (*.pem *.crt *.cer);;Alle Dateien (*)")
        if path:
            self.ca_file.setText(path)

    def form_profile(self) -> Profile:
        return replace(
            self.profile,
            name=self.name.text().strip() or self.host.text().strip() or "Verbindung",
            host=self.host.text().strip(), port=self.port.value(),
            security=self.security.currentData(), verify_cert=self.verify.isChecked(),
            ca_file=self.ca_file.text().strip(), auth=self.auth.currentData(),
            bind_dn=self.bind_dn.text().strip(), save_password=self.save_pw.isChecked(),
            base_dn=self.base_dn.text().strip(), read_only=self.read_only.isChecked(),
            timeout=self.timeout.value(), page_size=self.page_size.value(),
            password_scheme=self.pw_scheme.currentData(),
        )

    def _open_test_session(self):
        p = self.form_profile()
        if not p.host:
            QMessageBox.warning(self, APP_NAME, "Bitte einen Server angeben.")
            return FAIL
        pw = self.pw.text()
        if p.auth == "simple" and not pw:
            pw, ok = QInputDialog.getText(self, "Passwort", f"Passwort für {p.bind_dn or 'Bind'}:",
                                          QLineEdit.EchoMode.Password)
            if not ok:
                return FAIL
        return run_safely(self, "Verbindungstest", LdapSession.open, p, pw)

    def _test(self):
        session = self._open_test_session()
        if session is FAIL:
            return
        info = session.conn.server.info
        vendor = ""
        if info and info.vendor_name:
            vendor = f"\nServer: {', '.join(map(str, info.vendor_name))}"
            if info.vendor_version:
                vendor += f" {', '.join(map(str, info.vendor_version))}"
        roots = "\n".join(session.roots()) or "–"
        tls = "ja" if session.conn.tls_started or session.profile.security == "ldaps" else "nein"
        session.close()
        QMessageBox.information(self, "Verbindungstest",
                                f"Verbindung erfolgreich.{vendor}\nVerschlüsselt: {tls}\n\n"
                                f"Naming Contexts:\n{roots}")

    def _detect_base(self):
        session = self._open_test_session()
        if session is FAIL:
            return
        info = session.conn.server.info
        contexts = [str(c) for c in (info.naming_contexts or [])] if info else []
        session.close()
        if not contexts:
            QMessageBox.information(self, APP_NAME, "Der Server meldet keine Naming Contexts.")
        elif len(contexts) == 1:
            self.base_dn.setText(contexts[0])
        else:
            choice, ok = QInputDialog.getItem(self, "Basis-DN", "Naming Context wählen:",
                                              contexts, 0, False)
            if ok:
                self.base_dn.setText(choice)

    def _accept(self):
        p = self.form_profile()
        if not p.host:
            QMessageBox.warning(self, APP_NAME, "Bitte einen Server angeben.")
            return
        self.profile = p
        self.password = self.pw.text()
        self.accept()


class ConnectionManagerDialog(SizeMemory, QDialog):
    def __init__(self, store: ProfileStore, parent=None):
        super().__init__(parent)
        self.store = store
        self.selected: Profile | None = None
        self.selected_password: str | None = None
        self.setWindowTitle("Verbindungen")
        self.resize(560, 400)

        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda *_: self._connect())
        self.list.currentRowChanged.connect(self._update_buttons)

        self.btn_new = QPushButton("Neu…")
        self.btn_edit = QPushButton("Bearbeiten…")
        self.btn_dup = QPushButton("Duplizieren")
        self.btn_del = QPushButton("Löschen")
        self.btn_up = QPushButton("▲")
        self.btn_down = QPushButton("▼")
        self.btn_new.clicked.connect(self._new)
        self.btn_edit.clicked.connect(self._edit)
        self.btn_dup.clicked.connect(self._duplicate)
        self.btn_del.clicked.connect(self._delete)
        self.btn_up.clicked.connect(lambda *_: self._move(-1))
        self.btn_down.clicked.connect(lambda *_: self._move(1))
        side = QVBoxLayout()
        for b in (self.btn_new, self.btn_edit, self.btn_dup, self.btn_del):
            side.addWidget(b)
        arrows = QHBoxLayout()
        arrows.addWidget(self.btn_up)
        arrows.addWidget(self.btn_down)
        side.addLayout(arrows)
        side.addStretch()

        top = QHBoxLayout()
        top.addWidget(self.list, 1)
        top.addLayout(side)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.btn_connect = buttons.addButton("Verbinden", QDialogButtonBox.ButtonRole.AcceptRole)
        self.btn_connect.setDefault(True)
        self.btn_connect.clicked.connect(self._connect)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(buttons)
        self._refresh()

    def _refresh(self, select: int = 0):
        self.list.clear()
        for p in self.store.profiles:
            flags = []
            if p.security != "none":
                flags.append("TLS")
            if p.read_only:
                flags.append("nur lesen")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            item = QListWidgetItem(f"{p.name}\n    {p.url()}  ·  {p.bind_dn or 'anonym'}{suffix}")
            item.setIcon(std_icon(self, "SP_DriveNetIcon"))
            self.list.addItem(item)
        if self.store.profiles:
            self.list.setCurrentRow(max(0, min(select, len(self.store.profiles) - 1)))
        self.list.setMinimumWidth(fit_list_width(self.list, 360))
        hint = self.sizeHint().width()
        if self.width() < hint:
            self.resize(hint, self.height())
        self._update_buttons()

    def _update_buttons(self, *_):
        has = self.list.currentRow() >= 0
        for b in (self.btn_edit, self.btn_dup, self.btn_del, self.btn_connect,
                  self.btn_up, self.btn_down):
            b.setEnabled(has)

    def _current(self) -> Profile | None:
        row = self.list.currentRow()
        return self.store.profiles[row] if 0 <= row < len(self.store.profiles) else None

    def _apply_password(self, dlg: ConnectionDialog):
        p = dlg.profile
        if p.save_password and dlg.password:
            if not self.store.set_password(p, dlg.password):
                QMessageBox.warning(self, APP_NAME, "Passwort konnte nicht im Schlüsselbund "
                                                    "gespeichert werden.")
                p.save_password = False
        elif not p.save_password:
            self.store.delete_password(p)

    def _new(self):
        dlg = ConnectionDialog(self.store, Profile(), self)
        if dlg.exec():
            self.store.profiles.append(dlg.profile)
            self._apply_password(dlg)
            self.store.save()
            self._refresh(len(self.store.profiles) - 1)

    def _edit(self):
        row = self.list.currentRow()
        p = self._current()
        if not p:
            return
        dlg = ConnectionDialog(self.store, p, self)
        if dlg.exec():
            self.store.profiles[row] = dlg.profile
            self._apply_password(dlg)
            self.store.save()
            self._refresh(row)

    def _duplicate(self):
        p = self._current()
        if not p:
            return
        import uuid
        copy = replace(p, name=f"{p.name} (Kopie)", id=uuid.uuid4().hex, save_password=False)
        self.store.profiles.append(copy)
        self.store.save()
        self._refresh(len(self.store.profiles) - 1)

    def _delete(self):
        row = self.list.currentRow()
        p = self._current()
        if not p:
            return
        if QMessageBox.question(self, APP_NAME, f"Verbindung „{p.name}“ löschen?") \
                != QMessageBox.StandardButton.Yes:
            return
        self.store.delete_password(p)
        del self.store.profiles[row]
        self.store.save()
        self._refresh(row)

    def _move(self, delta: int):
        row = self.list.currentRow()
        new = row + delta
        if 0 <= row < len(self.store.profiles) and 0 <= new < len(self.store.profiles):
            ps = self.store.profiles
            ps[row], ps[new] = ps[new], ps[row]
            self.store.save()
            self._refresh(new)

    def _connect(self):
        p = self._current()
        if not p:
            return
        self.selected = p
        self.accept()


# =========================================================================== #
# Dialoge für Einträge
# =========================================================================== #
TEMPLATES = {
    "Organisationseinheit (OU)": ("ou=Neue Einheit", "top, organizationalUnit", "description: "),
    "Person (inetOrgPerson)": ("cn=Vorname Nachname",
                               "top, person, organizationalPerson, inetOrgPerson",
                               "sn: Nachname\ngivenName: Vorname\nmail: \nuid: \ntelephoneNumber: \n"
                               "userPassword: "),
    "POSIX-Benutzer": ("uid=benutzer",
                       "top, person, organizationalPerson, inetOrgPerson, posixAccount",
                       "cn: Vorname Nachname\nsn: Nachname\nuidNumber: 10000\ngidNumber: 10000\n"
                       "homeDirectory: /home/benutzer\nloginShell: /bin/bash\nmail: \n"
                       "userPassword: "),
    "Gruppe (groupOfNames)": ("cn=gruppe", "top, groupOfNames",
                              "member: \ndescription: "),
    "POSIX-Gruppe": ("cn=gruppe", "top, posixGroup", "gidNumber: 10000\nmemberUid: "),
    "Leer": ("", "top", ""),
}


class NewEntryDialog(SizeMemory, QDialog):
    def __init__(self, parent_dn: str, object_classes: list[str], parent=None,
                 copy: dict | None = None, group_count: int = 0):
        super().__init__(parent)
        self.setWindowTitle("Neuer Eintrag" if copy is None else
                           f"Neuer Eintrag auf Basis von {rdn_of(copy['source'])}")
        self.resize(780, 560)
        self.parent_dn = QLineEdit(parent_dn)
        self._templates = dict(TEMPLATES)
        self.template = QComboBox()
        copy_name = None
        if copy is not None:
            copy_name = f"Kopie von {rdn_of(copy['source'])}"
            self._templates = {copy_name: (copy["rdn"], copy["oc"], copy["attrs"]),
                               **self._templates}
        self.template.addItems(list(self._templates))
        self.template.currentTextChanged.connect(self._apply_template)
        self.rdn = QLineEdit()
        self.oc = QLineEdit()
        if object_classes:
            self.oc.setToolTip("Bekannte Objektklassen: " + ", ".join(object_classes[:40]) + " …")
        self.attrs = QPlainTextEdit()
        self.attrs.setPlaceholderText("attribut: wert   (eine Zeile pro Wert, leere Werte werden ignoriert)")
        mono = QFont("Menlo" if sys.platform == "darwin" else "Monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.attrs.setFont(mono)

        form = make_form()
        for w in (self.parent_dn, self.rdn, self.oc):
            w.setMinimumWidth(460)
        self.oc.setPlaceholderText("z. B. top, person, organizationalPerson, inetOrgPerson")
        form.addRow("Vorlage:", self.template)
        form.addRow("Übergeordneter DN:", self.parent_dn)
        form.addRow("RDN:", self.rdn)
        form.addRow("Objektklassen:", self.oc)
        form.addRow(QLabel("Attribute:"))
        self.copy_groups = QCheckBox(f"Gruppenzugehörigkeiten übernehmen ({group_count} "
                                     f"{'Gruppe' if group_count == 1 else 'Gruppen'})")
        self.copy_groups.setChecked(group_count > 0)
        self.copy_groups.setVisible(group_count > 0)
        note = QLabel("")
        note.setWordWrap(True)
        if copy is not None:
            hints = ["Leere Zeilen (z. B. Name, Mail, Passwort) bitte ausfüllen – leer gelassene "
                     "werden ignoriert."]
            if copy.get("skipped"):
                hints.append("Nicht übernommen: " + ", ".join(copy["skipped"]) + ".")
            note.setText(" ".join(hints))
        note.setVisible(copy is not None)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.attrs, 1)
        layout.addWidget(note)
        layout.addWidget(self.copy_groups)
        layout.addWidget(buttons)
        names = list(self._templates)
        self.template.setCurrentIndex(names.index(copy_name) if copy_name
                                      else names.index("Person (inetOrgPerson)"))
        self._apply_template(self.template.currentText())
        self.rdn.setFocus()
        self.rdn.setCursorPosition(len(self.rdn.text()))

    def _apply_template(self, name):
        rdn, oc, attrs = self._templates.get(name, ("", "top", ""))
        self.rdn.setText(rdn)
        self.oc.setText(oc)
        self.attrs.setPlainText(attrs)

    def _accept(self):
        rdn = self.rdn.text().strip()
        if "=" not in rdn or not rdn.split("=", 1)[1].strip():
            QMessageBox.warning(self, APP_NAME, "Der RDN muss die Form attribut=wert haben, "
                                                "z. B. cn=Max Muster.")
            return
        classes = [c.strip() for c in self.oc.text().split(",") if c.strip()]
        if not classes:
            QMessageBox.warning(self, APP_NAME, "Mindestens eine Objektklasse angeben.")
            return
        attributes: dict[str, list[str]] = {}
        for lineno, line in enumerate(self.attrs.toPlainText().splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if ":" not in line:
                QMessageBox.warning(self, APP_NAME, f"Zeile {lineno}: „attribut: wert“ erwartet.")
                return
            name, value = line.split(":", 1)
            name, value = name.strip(), value.strip()
            if name and value:
                attributes.setdefault(name, []).append(value)
        rdn_attr, rdn_value = rdn.split("=", 1)
        rdn_attr, rdn_value = rdn_attr.strip(), rdn_value.strip().replace("\\,", ",")
        existing = {k.lower(): k for k in attributes}
        key = existing.get(rdn_attr.lower(), rdn_attr)
        if rdn_value not in attributes.get(key, []):
            attributes.setdefault(key, []).insert(0, rdn_value)
        parent = self.parent_dn.text().strip()
        self.result_dn = f"{rdn},{parent}" if parent else rdn
        self.result_classes = classes
        self.result_attrs = attributes
        self.accept()


class RenameDialog(SizeMemory, QDialog):
    def __init__(self, dn: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Umbenennen / Verschieben")
        self.setMinimumWidth(640)
        self.old_parent = parent_of(dn)
        self.rdn = QLineEdit(rdn_of(dn))
        self.parent_dn = QLineEdit(self.old_parent)
        self.delete_old = QCheckBox("Alten RDN-Wert aus dem Eintrag entfernen")
        self.delete_old.setChecked(True)
        form = make_form()
        form.addRow("Aktueller DN:", QLabel(dn))
        form.addRow("Neuer RDN:", self.rdn)
        form.addRow("Neuer übergeordneter DN:", self.parent_dn)
        form.addRow("", self.delete_old)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def new_parent(self) -> str | None:
        p = self.parent_dn.text().strip()
        return None if norm_dn(p) == norm_dn(self.old_parent) else p


def scheme_combo(current: str) -> QComboBox:
    combo = QComboBox()
    for key, label in PASSWORD_SCHEMES:
        combo.addItem(label, key)
    keys = [k for k, _ in PASSWORD_SCHEMES]
    combo.setCurrentIndex(keys.index(current) if current in keys else 0)
    return combo


class PasswordDialog(QDialog):
    def __init__(self, dn: str, scheme: str = "server", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Passwort setzen")
        self.setMinimumWidth(500)
        self.pw1 = QLineEdit()
        self.pw2 = QLineEdit()
        for w in (self.pw1, self.pw2):
            w.setEchoMode(QLineEdit.EchoMode.Password)
        self.scheme = scheme_combo(scheme)
        self.scheme.setToolTip("„Server entscheidet“ überlässt das Hashen dem Server (z. B. "
                               "OpenLDAP ppolicy/olcPasswordHash). Sonst erzeugt LDAP Admin den "
                               "Hash selbst – der Server sieht das Passwort nie im Klartext.")
        form = make_form()
        form.addRow("Eintrag:", QLabel(rdn_of(dn)))
        form.addRow("Neues Passwort:", self.pw1)
        form.addRow("Wiederholen:", self.pw2)
        form.addRow("Speicherformat:", self.scheme)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _accept(self):
        if not self.pw1.text():
            QMessageBox.warning(self, APP_NAME, "Bitte ein Passwort eingeben.")
        elif self.pw1.text() != self.pw2.text():
            QMessageBox.warning(self, APP_NAME, "Die Passwörter stimmen nicht überein.")
        elif self.scheme.currentData() == "plain" and QMessageBox.question(
                self, APP_NAME, "Das Passwort wird im Klartext gespeichert und ist für jeden "
                                "mit Lesezugriff sichtbar. Wirklich fortfahren?") \
                != QMessageBox.StandardButton.Yes:
            return
        else:
            self.accept()


class AddValueDialog(SizeMemory, QDialog):
    def __init__(self, attr_names: list[str], preset: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Wert hinzufügen")
        self.setMinimumWidth(460)
        self.attr = QComboBox()
        self.attr.setEditable(True)
        self.attr.addItems(attr_names)
        self.attr.setCurrentText(preset)
        self.attr.completer().setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.attr.completer().setFilterMode(Qt.MatchFlag.MatchContains)
        self.value = QLineEdit()
        form = make_form()
        form.addRow("Attribut:", self.attr)
        form.addRow("Wert:", self.value)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)
        (self.value if preset else self.attr).setFocus()

    def _accept(self):
        if not self.attr.currentText().strip() or not self.value.text():
            QMessageBox.warning(self, APP_NAME, "Attribut und Wert angeben.")
            return
        self.accept()


class _PickerDialog(SizeMemory, QDialog):
    """Zwei Listen: links aktuelle Zuordnungen, rechts Suchergebnisse zum Hinzufügen."""

    def __init__(self, title: str, left_title: str, search_hint: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(860, 520)
        self.current = QListWidget()
        self.current.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.current.setSortingEnabled(True)
        self.results = QListWidget()
        self.results.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.results.itemDoubleClicked.connect(lambda *_: self._add())
        self.current.itemDoubleClicked.connect(lambda *_: self._remove())
        self.query = QLineEdit()
        self.query.setPlaceholderText(search_hint)
        self.query.returnPressed.connect(self._search)
        go = QPushButton("Suchen")
        go.clicked.connect(self._search)
        add = QPushButton("◀  Hinzufügen")
        rem = QPushButton("Entfernen  ▶")
        add.clicked.connect(self._add)
        rem.clicked.connect(self._remove)
        self.left_label = QLabel(left_title)
        self.info = QLabel("")

        left = QVBoxLayout()
        left.addWidget(self.left_label)
        left.addWidget(self.current, 1)
        mid = QVBoxLayout()
        mid.addStretch()
        mid.addWidget(add)
        mid.addWidget(rem)
        mid.addStretch()
        right = QVBoxLayout()
        row = QHBoxLayout()
        row.addWidget(self.query, 1)
        row.addWidget(go)
        right.addLayout(row)
        right.addWidget(self.results, 1)
        lists = QHBoxLayout()
        lists.addLayout(left, 1)
        lists.addLayout(mid)
        lists.addLayout(right, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        bottom = QHBoxLayout()
        bottom.addWidget(self.info, 1)
        bottom.addWidget(buttons)
        layout = QVBoxLayout(self)
        layout.addLayout(lists, 1)
        layout.addLayout(bottom)

    def _item(self, label: str, key: str, tooltip: str = "") -> QListWidgetItem:
        item = QListWidgetItem(label)
        item.setData(ROLE_DN, key)
        item.setToolTip(tooltip or key)
        return item

    def current_keys(self) -> list[str]:
        return [self.current.item(i).data(ROLE_DN) for i in range(self.current.count())]

    def _has(self, key: str) -> bool:
        return any(norm_dn(k) == norm_dn(key) or k.lower() == key.lower()
                   for k in self.current_keys())

    def _add(self):
        for item in self.results.selectedItems():
            key = self.member_key(item)
            if key and not self._has(key):
                self.current.addItem(self._item(item.text(), key, item.toolTip()))
        self._changed()

    def _remove(self):
        for item in self.current.selectedItems():
            self.current.takeItem(self.current.row(item))
        self._changed()

    def _changed(self):
        self.left_label.setText(f"{self.left_title_base} ({self.current.count()})")

    def member_key(self, item) -> str | None:  # in Unterklassen überschrieben
        return item.data(ROLE_DN)


class GroupMembersDialog(_PickerDialog):
    def __init__(self, sw: "SessionWidget", group_dn: str, attr: str, kind: str, members: list[str]):
        super().__init__(f"Mitglieder – {rdn_of(group_dn)}", "Mitglieder",
                         "Benutzer suchen (Name, uid, Mail) …", sw)
        self.sw, self.group_dn, self.attr, self.kind = sw, group_dn, attr, kind
        self.old = list(members)
        self.left_title_base = f"Mitglieder ({attr})"
        for m in members:
            self.current.addItem(self._item(rdn_of(m) if kind == "dn" else m, m))
        self._changed()
        self.info.setText("Doppelklick fügt hinzu bzw. entfernt. Änderungen erst mit „Speichern“.")
        self._search()

    def _search(self):
        res = run_safely(self, "Suche", self.sw.session.find_entries, self.query.text(), "user")
        if res is FAIL:
            return
        self.results.clear()
        for e in res:
            item = self._item(e["label"], e["dn"], e["dn"])
            item.setData(ROLE_RAW, e["uid"])
            self.results.addItem(item)

    def member_key(self, item) -> str | None:
        if self.kind == "dn":
            return item.data(ROLE_DN)
        uid = item.data(ROLE_RAW)
        if not uid:
            QMessageBox.warning(self, APP_NAME, f"{item.text()} hat kein uid-Attribut und kann "
                                                "nicht in eine POSIX-Gruppe aufgenommen werden.")
        return uid or None

    def _save(self):
        new = self.current_keys()
        if not new and self.attr.lower() in ("member", "uniquemember"):
            QMessageBox.warning(self, APP_NAME, "Diese Gruppenart braucht mindestens ein Mitglied.")
            return
        if run_safely(self, "Mitglieder speichern", self.sw.session.set_group_members,
                      self.group_dn, self.attr, self.old, new) is FAIL:
            return
        self.accept()


class UserGroupsDialog(_PickerDialog):
    def __init__(self, sw: "SessionWidget", user_dn: str, groups: list[dict]):
        super().__init__(f"Gruppen – {rdn_of(user_dn)}", "Mitglied in",
                         "Gruppen suchen …", sw)
        self.sw, self.user_dn = sw, user_dn
        self.old = {g["dn"] for g in groups}
        self.left_title_base = "Mitglied in"
        for g in groups:
            self.current.addItem(self._item(g["label"], g["dn"]))
        self._changed()
        self.info.setText("Doppelklick fügt hinzu bzw. entfernt. Änderungen erst mit „Speichern“.")
        self._search()

    def _search(self):
        res = run_safely(self, "Suche", self.sw.session.find_entries, self.query.text(), "group")
        if res is FAIL:
            return
        self.results.clear()
        for e in res:
            self.results.addItem(self._item(e["label"], e["dn"]))

    def _save(self):
        new = set(self.current_keys())
        old_n = {norm_dn(d): d for d in self.old}
        new_n = {norm_dn(d): d for d in new}
        errors = []
        with busy():
            for key, dn in new_n.items():
                if key not in old_n:
                    try:
                        self.sw.session.add_to_group(dn, self.user_dn)
                    except (LdapError, LDAPException) as exc:
                        errors.append(f"{rdn_of(dn)}: {exc}")
            for key, dn in old_n.items():
                if key not in new_n:
                    try:
                        self.sw.session.remove_from_group(dn, self.user_dn)
                    except (LdapError, LDAPException) as exc:
                        errors.append(f"{rdn_of(dn)}: {exc}")
        if errors:
            QMessageBox.warning(self, APP_NAME, "Nicht alle Änderungen waren möglich:\n\n" +
                                "\n".join(errors))
        self.accept()


class ImportDialog(SizeMemory, QDialog):
    ON_EXISTS = [("Überspringen", "skip"), ("Attribute ersetzen", "replace"),
                 ("Als Fehler werten", "error")]

    def __init__(self, sw: "SessionWidget"):
        super().__init__(sw)
        self.sw = sw
        self.records = []
        self.imported = False
        self.setWindowTitle(f"LDIF-Import – {sw.session.profile.name}")
        self.resize(820, 600)
        self.path = QLineEdit()
        self.path.setReadOnly(True)
        browse = QPushButton("Datei wählen…")
        browse.clicked.connect(self._pick)
        row = QHBoxLayout()
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        self.summary = QLabel("Noch keine Datei geladen.")
        self.on_exists = QComboBox()
        for label, key in self.ON_EXISTS:
            self.on_exists.addItem(label, key)
        self.cont = QCheckBox("Bei Fehlern mit dem nächsten Eintrag weitermachen")
        self.cont.setChecked(True)
        scheme = local_scheme(sw.session.profile.password_scheme)
        self.hash_pw = QCheckBox(f"Klartext-Passwörter (userPassword) als {{{scheme}}} speichern")
        self.hash_pw.setChecked(scheme != "plain")
        self.hash_pw.setEnabled(scheme != "plain")
        self.hash_scheme = scheme
        self.suffix_from = QLineEdit()
        self.suffix_from.setPlaceholderText("z. B. dc=alt,dc=ch  (optional)")
        self.suffix_to = QLineEdit(sw.session.roots()[0] if sw.session.roots() else "")
        form = make_form()
        form.addRow("Datei:", row)
        form.addRow("", self.summary)
        form.addRow("Eintrag existiert:", self.on_exists)
        form.addRow("", self.cont)
        form.addRow("", self.hash_pw)
        form.addRow("Basis-DN ersetzen von:", self.suffix_from)
        form.addRow("… durch:", self.suffix_to)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        mono = QFont("Menlo" if sys.platform == "darwin" else "Monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.log.setFont(mono)
        self.progress = QLabel("")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.btn_test = buttons.addButton("Testlauf", QDialogButtonBox.ButtonRole.ActionRole)
        self.btn_run = buttons.addButton("Importieren", QDialogButtonBox.ButtonRole.ActionRole)
        self.btn_test.clicked.connect(lambda *_: self._run(dry=True))
        self.btn_run.clicked.connect(lambda *_: self._run(dry=False))
        buttons.rejected.connect(self.reject)
        for b in (self.btn_test, self.btn_run):
            b.setEnabled(False)
        bottom = QHBoxLayout()
        bottom.addWidget(self.progress, 1)
        bottom.addWidget(buttons)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.log, 1)
        layout.addLayout(bottom)

    def _pick(self):
        path, _ = QFileDialog.getOpenFileName(self, "LDIF-Datei öffnen", "",
                                              "LDIF (*.ldif *.ldf);;Alle Dateien (*)")
        if path:
            self.load(path)

    def load(self, path: str):
        try:
            with open(path, encoding="utf-8-sig") as fh:
                text = fh.read()
            self.records = parse_ldif(text, os.path.dirname(path))
        except (OSError, UnicodeDecodeError, LdapError, ValueError) as exc:
            QMessageBox.critical(self, "LDIF-Import", f"Datei kann nicht gelesen werden:\n{exc}")
            return
        self.path.setText(path)
        counts = Counter(r.changetype for r in self.records)
        parts = ", ".join(f"{n}× {t}" for t, n in sorted(counts.items()))
        self.summary.setText(f"{len(self.records)} Datensätze ({parts or 'leer'})")
        plain = sum(1 for r in self.records
                    for n, vals in list(r.attrs.items()) + [(m[1], m[2]) for m in r.mods]
                    if n.lower() == "userpassword"
                    for v in vals if not is_hashed(v) and not isinstance(v, bytes))
        if plain:
            self.summary.setText(self.summary.text() + f" – davon {plain} Klartext-Passwort/-wörter")
        # Basis-DN der Datei vorschlagen, wenn sie nicht zum Server passt
        target = self.suffix_to.text().strip()
        if self.records and target and not self.suffix_from.text():
            first = self.records[0].dn
            if not norm_dn(first).endswith(norm_dn(target)):
                parts_dn = split_dn(first)
                guess = ",".join(p for p in parts_dn if p.lower().startswith("dc="))
                if guess:
                    self.suffix_from.setText(guess)
        self.log.setPlainText("\n".join(f"{r.changetype:7} {r.dn}" for r in self.records[:500]) +
                              ("\n…" if len(self.records) > 500 else ""))
        for b in (self.btn_test, self.btn_run):
            b.setEnabled(bool(self.records))

    def _run(self, dry: bool):
        if not self.records:
            return
        if not dry and QMessageBox.question(
                self, "LDIF-Import",
                f"{len(self.records)} Datensätze in {self.sw.session.profile.url()} importieren?") \
                != QMessageBox.StandardButton.Yes:
            return

        def progress(i, total, dn):
            if i % 25 == 0 or i == total:
                self.progress.setText(f"{i} / {total}")
                QApplication.processEvents()

        stats = run_safely(self, "LDIF-Import", self.sw.session.import_records, self.records,
                           on_exists=self.on_exists.currentData(),
                           continue_on_error=self.cont.isChecked(),
                           hash_scheme=self.hash_scheme if self.hash_pw.isChecked() else None,
                           suffix_from=self.suffix_from.text().strip(),
                           suffix_to=self.suffix_to.text().strip(), dry_run=dry,
                           progress=progress)
        if stats is FAIL:
            return
        head = "Testlauf (nichts geändert)" if dry else "Import abgeschlossen"
        self.progress.setText(f"{head}: {stats['ok']} ok, {stats['skipped']} übersprungen, "
                              f"{stats['failed']} Fehler")
        self.log.setPlainText("\n".join(stats["log"]))
        if not dry:
            self.imported = True


class SearchDialog(SizeMemory, QDialog):
    SCOPES = [("Gesamter Unterbaum", SUBTREE), ("Eine Ebene", LEVEL), ("Nur Basis", BASE)]

    def __init__(self, session_widget: "SessionWidget", base: str):
        super().__init__(session_widget)
        self.sw = session_widget
        self.setWindowTitle(f"Suche – {session_widget.session.profile.name}")
        self.resize(820, 520)
        self.base = QLineEdit(base)
        self.filter = QLineEdit("(objectClass=*)")
        self.filter.setPlaceholderText("z. B. (&(objectClass=person)(mail=*@firma.ch))")
        self.scope = QComboBox()
        for label, scope in self.SCOPES:
            self.scope.addItem(label, scope)
        self.attrs = QLineEdit("cn, mail")
        self.attrs.setPlaceholderText("Kommagetrennte Attribute für die Spalten")
        self.limit = QSpinBox()
        self.limit.setRange(1, 1_000_000)
        self.limit.setValue(1000)
        go = QPushButton("Suchen")
        go.setDefault(True)
        go.clicked.connect(self._search)
        self.export_btn = QPushButton("Als CSV exportieren…")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export)

        form = make_form()
        form.addRow("Basis-DN:", self.base)
        form.addRow("Filter:", self.filter)
        row = QHBoxLayout()
        row.addWidget(self.scope)
        row.addWidget(QLabel("Max. Treffer:"))
        row.addWidget(self.limit)
        row.addStretch()
        form.addRow("Bereich:", row)
        form.addRow("Spalten:", self.attrs)

        self.table = QTableWidget(0, 1)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.cellDoubleClicked.connect(self._open)
        self.status = QLabel("Doppelklick auf einen Treffer öffnet ihn im Hauptfenster.")

        bottom = QHBoxLayout()
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.export_btn)
        bottom.addWidget(go)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.table, 1)
        layout.addLayout(bottom)

    def _search(self):
        cols = [a.strip() for a in self.attrs.text().split(",") if a.strip()]
        flt = self.filter.text().strip() or "(objectClass=*)"
        if not flt.startswith("("):
            flt = f"({flt})"
        res = run_safely(self, "Suche", self.sw.session.search, self.base.text().strip(), flt,
                         self.scope.currentData(), cols or ["1.1"], self.limit.value())
        if res is FAIL:
            return
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.table.setColumnCount(1 + len(cols))
        self.table.setHorizontalHeaderLabels(["DN"] + cols)
        self.table.setRowCount(len(res))
        for row, entry in enumerate(res):
            self.table.setItem(row, 0, QTableWidgetItem(entry["dn"]))
            raw = {k.lower(): v for k, v in (entry.get("raw_attributes") or {}).items()}
            for col, name in enumerate(cols, 1):
                vals = []
                for v in raw.get(name.lower(), []):
                    text = decode_value(name, v) if isinstance(v, bytes) else str(v)
                    vals.append(text if text is not None else f"<binär, {len(v)} Bytes>")
                self.table.setItem(row, col, QTableWidgetItem("; ".join(vals)))
        self.table.setSortingEnabled(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.resizeColumnsToContents()
        header.setStretchLastSection(True)
        more = " (Limit erreicht)" if len(res) >= self.limit.value() else ""
        self.status.setText(f"{len(res)} Treffer{more}")
        self.export_btn.setEnabled(bool(res))

    def _open(self, row, _col):
        item = self.table.item(row, 0)
        if item:
            self.sw.open_dn(item.text())
            self.sw.window().raise_()
            self.sw.window().activateWindow()

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "CSV speichern", "suchergebnis.csv",
                                              "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.writer(fh, delimiter=";")
                w.writerow([self.table.horizontalHeaderItem(c).text()
                            for c in range(self.table.columnCount())])
                for r in range(self.table.rowCount()):
                    w.writerow([(self.table.item(r, c).text() if self.table.item(r, c) else "")
                                for c in range(self.table.columnCount())])
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, str(exc))
            return
        self.status.setText(f"{self.table.rowCount()} Zeilen exportiert nach {path}")


# =========================================================================== #
# Verzeichnisbaum mit Drag & Drop
# =========================================================================== #
class LdapTree(QTreeWidget):
    """Einträge per Ziehen verschieben oder kopieren. Der Baum selbst wird dabei nicht
    von Qt verändert – die Änderung macht der Server, danach wird neu geladen."""

    COPY_KEYS = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier

    def __init__(self):
        super().__init__()
        self.drop_handler = None          # callable(src_dn, target_dn, mode) – mode: move|copy|None
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setAutoExpandDelay(700)      # beim Darüberhalten aufklappen

    def _source_dn(self):
        item = self.currentItem()
        return item.data(0, ROLE_DN) if item is not None else None

    def _target_dn(self, event):
        item = self.itemAt(event.position().toPoint())
        return item.data(0, ROLE_DN) if item is not None else None

    def _valid(self, event):
        if event.source() is not self or self.drop_handler is None:
            return None
        src, tgt = self._source_dn(), self._target_dn(event)
        if src is None or tgt is None or LdapSession.is_same_or_below(tgt, src):
            return None
        return src, tgt

    def dragEnterEvent(self, event):
        if event.source() is self and self._source_dn() is not None:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        super().dragMoveEvent(event)      # Autoscroll und automatisches Aufklappen
        if self._valid(event):
            copy = bool(event.modifiers() & self.COPY_KEYS)
            event.setDropAction(Qt.DropAction.CopyAction if copy else Qt.DropAction.MoveAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        pair = self._valid(event)
        mods = event.modifiers()
        event.setDropAction(Qt.DropAction.IgnoreAction)   # Qt soll nichts selbst verschieben
        event.accept()
        if not pair:
            return
        mode = "copy" if mods & self.COPY_KEYS else \
            "move" if mods & Qt.KeyboardModifier.ShiftModifier else None
        src, tgt = pair
        QTimer.singleShot(0, lambda: self.drop_handler(src, tgt, mode))


# =========================================================================== #
# Eine geöffnete Verbindung (Tab)
# =========================================================================== #
class SessionWidget(QWidget):
    def __init__(self, session: LdapSession, main: "MainWindow"):
        super().__init__()
        self.session = session
        self.main = main
        self.read_only = session.profile.read_only
        self.current_dn: str | None = None
        self.original: dict[str, list[bytes]] = {}
        self.dirty = False
        self._loading = False
        self._search_dialogs: list[SearchDialog] = []
        self._attr_names = session.attribute_names()

        # Werkzeugleiste ----------------------------------------------------------
        tb = QToolBar()
        tb.setMovable(False)
        self.toolbar = tb

        def act(text, icon, slot, shortcut=None, write=False, needs_entry=True, tip=None):
            a = QAction(std_icon(self, icon), text, self)
            a.triggered.connect(slot)
            tip = tip or text
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
                a.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
                native = QKeySequence(shortcut).toString(QKeySequence.SequenceFormat.NativeText)
                tip = f"{tip}  ({native})"
            a.setToolTip(tip)
            a.setProperty("write", write)
            a.setProperty("needs_entry", needs_entry)
            tb.addAction(a)
            return a

        self.act_refresh = act("Aktualisieren", "SP_BrowserReload", self.refresh, "F5")
        tb.addSeparator()
        self.act_new = act("Neu", "SP_FileDialogNewFolder", self.new_entry, "Ctrl+N", write=True,
                           tip="Neuer Eintrag unterhalb des ausgewählten")
        self.act_duplicate = act("Duplizieren", "SP_FileIcon", self.duplicate_entry, "Ctrl+D",
                                 write=True, tip="Neuer Eintrag auf Basis des ausgewählten")
        self.act_rename = act("Verschieben", "SP_FileDialogDetailedView",
                              self.rename_entry, "F2", write=True,
                              tip="Umbenennen / Verschieben")
        self.act_delete = act("Löschen", "SP_TrashIcon", self.delete_entry, "Del", write=True)
        self.act_password = act("Passwort", "SP_DialogApplyButton", self.set_password, write=True)
        self.act_groups = act("Gruppen", "SP_DirLinkIcon", self.manage_groups, "Ctrl+G", write=True)
        self.act_groups.setToolTip("Gruppe: Mitglieder verwalten · Benutzer: Gruppenzugehörigkeiten")
        tb.addSeparator()
        self.act_search = act("Suchen", "SP_FileDialogContentsView", self.open_search, "Ctrl+F",
                              needs_entry=False)
        self.act_export = act("Export", "SP_DialogSaveButton", self.export_ldif,
                              tip="LDIF-Export des ausgewählten Teilbaums")
        self.act_import = act("Import", "SP_DialogOpenButton", self.import_ldif, write=True,
                              needs_entry=False, tip="LDIF-Import")
        self.act_info = act("Info", "SP_MessageBoxInformation", self.server_info,
                            needs_entry=False, tip="Server-Info (Root DSE)")
        tb.addSeparator()
        self.act_operational = QAction(std_icon(self, "SP_FileDialogInfoView"), "Intern", self)
        self.act_operational.setCheckable(True)
        self.act_operational.setToolTip("Operative Attribute anzeigen, z. B. createTimestamp "
                                        "(nur lesen)")
        self.act_operational.toggled.connect(lambda _: self.current_dn and self.load_entry(self.current_dn))
        tb.addAction(self.act_operational)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        self.act_logout = QAction(std_icon(self, "SP_DialogCloseButton"), "Abmelden", self)
        self.act_logout.setToolTip("Verbindung trennen (Unbind) und Tab schließen – Strg/⌘+W")
        self.act_logout.triggered.connect(lambda *_: self.main.close_tab(self.main.tabs.indexOf(self)))
        tb.addAction(self.act_logout)
        apply_toolbar_style(tb, main.toolbar_style)

        # Baum --------------------------------------------------------------------
        self.tree = LdapTree()
        self.tree.drop_handler = self.handle_drop
        if self.read_only:
            self.tree.setDragEnabled(False)
            self.tree.setAcceptDrops(False)
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.itemExpanded.connect(self._on_expanded)
        self.tree.currentItemChanged.connect(self._on_tree_selection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        sep = QAction(self)
        sep.setSeparator(True)
        sep2 = QAction(self)
        sep2.setSeparator(True)
        self.tree.addActions([self.act_new, self.act_duplicate, self.act_rename, sep,
                              self.act_groups, self.act_password, sep2, self.act_export,
                              self.act_refresh, self.act_delete])

        # Attribute ---------------------------------------------------------------
        self.dn_edit = QLineEdit()
        self.dn_edit.setReadOnly(True)
        self.dn_edit.setPlaceholderText("Eintrag im Baum auswählen")
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Attribut", "Wert"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setMinimumSectionSize(2)  # schmale Trennlinien
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked |
                                   QAbstractItemView.EditTrigger.EditKeyPressed |
                                   QAbstractItemView.EditTrigger.AnyKeyPressed)
        self.table.itemChanged.connect(self._on_item_changed)
        self.table.itemDoubleClicked.connect(self._on_double_click)
        self.table.itemSelectionChanged.connect(self._update_actions)

        self.btn_add = QPushButton(std_icon(self, "SP_FileDialogNewFolder"), "Wert hinzufügen")
        self.btn_remove = QPushButton(std_icon(self, "SP_DialogDiscardButton"), "Wert entfernen")
        self.btn_revert = QPushButton("Verwerfen")
        self.btn_save = QPushButton(std_icon(self, "SP_DialogSaveButton"), "Speichern")
        self.btn_save.setShortcut(QKeySequence("Ctrl+S"))
        self.btn_add.clicked.connect(self.add_value)
        self.btn_remove.clicked.connect(self.remove_values)
        self.btn_revert.clicked.connect(lambda *_: self.current_dn and self.load_entry(self.current_dn))
        self.btn_save.clicked.connect(self.save_changes)
        btns = QHBoxLayout()
        btns.addWidget(self.btn_add)
        btns.addWidget(self.btn_remove)
        btns.addStretch()
        btns.addWidget(self.btn_revert)
        btns.addWidget(self.btn_save)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.dn_edit)
        rl.addWidget(self.table, 1)
        rl.addLayout(btns)
        if self.read_only:
            banner = QLabel("Nur-Lesen-Modus: Änderungen sind für diese Verbindung deaktiviert.")
            banner.setStyleSheet("color: #8a6d00;")
            rl.insertWidget(0, banner)

        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([320, 680])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(tb)
        layout.addWidget(splitter, 1)

        self.populate_roots()
        self._update_actions()

    # Hilfen -----------------------------------------------------------------------
    def status(self, text: str, ms: int = 5000):
        self.main.statusBar().showMessage(text, ms)

    def _update_actions(self):
        has_entry = bool(self.current_dn is not None)
        for a in (self.act_refresh, self.act_new, self.act_rename, self.act_delete,
                  self.act_password, self.act_search, self.act_export, self.act_info,
                  self.act_import, self.act_groups, self.act_duplicate):
            enabled = (has_entry or not a.property("needs_entry")) and \
                      not (self.read_only and a.property("write"))
            a.setEnabled(enabled)
        self.act_refresh.setEnabled(True)
        kind = self._entry_kind()
        self.act_groups.setEnabled(has_entry and not self.read_only and kind is not None)
        self.act_groups.setText("Mitglieder" if kind == "group" else "Gruppen")
        self.act_password.setEnabled(has_entry and not self.read_only and kind != "group")
        writable = has_entry and not self.read_only
        self.btn_add.setEnabled(writable)
        self.btn_remove.setEnabled(writable and self._removable_rows() != [])
        self.btn_save.setEnabled(writable and self.dirty)
        self.btn_revert.setEnabled(has_entry and self.dirty)

    def _entry_kind(self) -> str | None:
        if self.current_dn is None or not self.original:
            return None
        if self.session.group_attr(self.original):
            return "group"
        if self.session.is_user(self.original):
            return "user"
        return None

    def _set_dirty(self, dirty: bool):
        self.dirty = dirty
        idx = self.main.tabs.indexOf(self)
        if idx >= 0:
            name = self.session.profile.name
            self.main.tabs.setTabText(idx, f"{name} *" if dirty else name)
        self._update_actions()

    # Baum -------------------------------------------------------------------------
    @staticmethod
    def _set_expandable(item: QTreeWidgetItem, has_children: bool | None):
        """Aufklapp-Pfeil nur zeigen, wenn es (vermutlich) Untereinträge gibt."""
        policy = QTreeWidgetItem.ChildIndicatorPolicy
        item.setChildIndicatorPolicy(policy.DontShowIndicator if has_children is False
                                     else policy.ShowIndicator)

    def _make_item(self, dn: str, label: str | None = None,
                   has_children: bool | None = None) -> QTreeWidgetItem:
        item = QTreeWidgetItem([label or rdn_of(dn)])
        item.setData(0, ROLE_DN, dn)
        item.setData(0, ROLE_LOADED, False)
        item.setToolTip(0, dn or "Root DSE")
        attr = rdn_of(dn).split("=", 1)[0].strip().lower() if dn else "dc"
        container = attr in CONTAINER_ATTRS or bool(has_children)
        item.setIcon(0, std_icon(self, "SP_DirIcon" if container else "SP_FileIcon"))
        self._set_expandable(item, has_children)
        return item

    def populate_roots(self):
        self.tree.clear()
        for dn in self.session.roots():
            self.tree.addTopLevelItem(self._make_item(dn, dn or "(Root DSE)"))
        if self.tree.topLevelItemCount() == 1:
            top = self.tree.topLevelItem(0)
            self.tree.expandItem(top)
            self.tree.setCurrentItem(top)

    def _on_expanded(self, item: QTreeWidgetItem):
        if not item.data(0, ROLE_LOADED):
            self._load_children(item)

    def _load_children(self, item: QTreeWidgetItem):
        dn = item.data(0, ROLE_DN)
        res = run_safely(self, "Unterknoten laden", self.session.children_info, dn)
        item.takeChildren()
        if res is FAIL:
            self._set_expandable(item, None)
            item.setData(0, ROLE_LOADED, False)
            return
        for child, has_children in res:
            item.addChild(self._make_item(child, has_children=has_children))
        item.setData(0, ROLE_LOADED, True)
        if not res:                       # doch keine Untereinträge: Pfeil entfernen
            self._set_expandable(item, False)
            item.setExpanded(False)
        if len(res) >= CHILD_LIMIT:
            self.status(f"Nur die ersten {CHILD_LIMIT} Unterknoten angezeigt – nutze die Suche.",
                        10000)

    def _reload_item(self, item: QTreeWidgetItem | None):
        if item is None:
            return
        expanded = item.isExpanded()
        item.setData(0, ROLE_LOADED, False)
        item.takeChildren()
        if expanded:
            self._load_children(item)
            item.setExpanded(bool(item.childCount()))
        else:
            dn = item.data(0, ROLE_DN)
            has = run_safely(self, "Aktualisieren", self.session.has_children, dn)
            self._set_expandable(item, None if has is FAIL else has)

    def find_item(self, dn: str) -> QTreeWidgetItem | None:
        target = norm_dn(dn)
        it = QTreeWidgetItemIterator(self.tree)
        while it.value():
            item = it.value()
            d = item.data(0, ROLE_DN)
            if d is not None and norm_dn(d) == target:
                return item
            it += 1
        return None

    def _on_tree_selection(self, cur, prev):
        if cur is None or cur.data(0, ROLE_DN) is None:
            return
        if not self.confirm_discard():
            self.tree.blockSignals(True)
            self.tree.setCurrentItem(prev)
            self.tree.blockSignals(False)
            return
        self.load_entry(cur.data(0, ROLE_DN))

    def open_dn(self, dn: str):
        """Öffnet einen DN (z. B. aus der Suche) und klappt den Baum soweit möglich auf."""
        if not self.confirm_discard():
            return
        parts = split_dn(dn)
        for i in range(len(parts) - 1, 0, -1):  # Vorfahren aufklappen
            item = self.find_item(",".join(parts[i:]))
            if item is not None and not item.isExpanded():
                item.setExpanded(True)
        item = self.find_item(dn)
        if item is not None:
            self.tree.blockSignals(True)
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item)
            self.tree.blockSignals(False)
        self.load_entry(dn)

    # Attribute --------------------------------------------------------------------
    def load_entry(self, dn: str):
        res = run_safely(self, "Eintrag lesen", self.session.read, dn,
                         self.act_operational.isChecked())
        if res is FAIL:
            return
        user, op = res
        self.current_dn = dn
        self.original = user
        self.dn_edit.setText(dn)
        rows = [(n, v, False) for n, vals in user.items() for v in vals]
        rows += [(n, v, True) for n, vals in op.items() for v in vals]
        self._render_rows(rows)
        self._set_dirty(False)

    # Sortierte Darstellung ----------------------------------------------------------
    @staticmethod
    def _value_key(value):
        if isinstance(value, bytes):
            try:
                return (0, value.decode("utf-8").lower())
            except UnicodeDecodeError:
                return (1, "")
        return (0, str(value).lower())

    def _render_rows(self, rows: list[tuple]) -> None:
        """Zeigt (Attribut, Wert, operativ)-Zeilen alphabetisch sortiert an:
        objectClass zuerst, dann die übrigen Attribute, dann operative – mit Trennlinien."""
        def key(r):
            return (r[0].lower(), self._value_key(r[1]))
        classes = sorted((r for r in rows if not r[2] and r[0].lower() == "objectclass"), key=key)
        others = sorted((r for r in rows if not r[2] and r[0].lower() != "objectclass"), key=key)
        operational = sorted((r for r in rows if r[2]), key=key)
        self._loading = True
        self.table.setRowCount(0)
        groups = [g for g in (classes, others, operational) if g]
        for i, group in enumerate(groups):
            if i > 0:
                self._append_separator()
            for name, value, op in group:
                self._append_row(name, value, operational=op)
        self._loading = False

    def _append_separator(self) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        sep = QTableWidgetItem("")
        sep.setFlags(Qt.ItemFlag.NoItemFlags)
        sep.setData(ROLE_SEP, True)
        sep.setBackground(QColor(128, 128, 128, 110))
        self.table.setItem(row, 0, sep)
        self.table.setSpan(row, 0, 1, 2)
        self.table.setRowHeight(row, 3)

    def _current_rows(self) -> list[tuple]:
        rows = []
        for r in range(self.table.rowCount()):
            a, v = self.table.item(r, 0), self.table.item(r, 1)
            if a is None or v is None or a.data(ROLE_SEP):
                continue
            raw = get_raw(v)
            rows.append((a.text(), raw if raw is not None else v.text(), bool(a.data(ROLE_OP))))
        return rows

    def _find_row(self, name: str, value) -> int:
        target = value.encode("utf-8") if isinstance(value, str) else value
        for r in range(self.table.rowCount()):
            a, v = self.table.item(r, 0), self.table.item(r, 1)
            if a is None or v is None or a.data(ROLE_SEP) or a.text().lower() != name.lower():
                continue
            raw = get_raw(v)
            if (raw if raw is not None else v.text().encode("utf-8")) == target:
                return r
        return -1

    def _append_row(self, name: str, value, operational: bool = False) -> int:
        row = self.table.rowCount()
        self.table.insertRow(row)
        a = QTableWidgetItem(name)
        a.setFlags(a.flags() & ~EDITABLE)
        text = value if isinstance(value, str) else decode_value(name, value)
        if name.lower() == "userpassword" and not operational:
            raw = value if isinstance(value, bytes) else value.encode("utf-8")
            v = QTableWidgetItem(describe_password(raw))
            v.setData(ROLE_RAW, Raw(raw))
            v.setFlags(v.flags() & ~EDITABLE)
            v.setToolTip("Passwörter werden nicht angezeigt. Doppelklick zum Ändern.")
            if not is_hashed(raw):
                v.setForeground(QColor(200, 60, 40))
        elif text is None:
            v = QTableWidgetItem(f"<binär, {len(value)} Bytes>")
            v.setData(ROLE_RAW, Raw(value))
            v.setFlags(v.flags() & ~EDITABLE)
            f = v.font()
            f.setItalic(True)
            v.setFont(f)
        else:
            v = QTableWidgetItem(text)
            if operational or self.read_only:
                v.setFlags(v.flags() & ~EDITABLE)
        if operational:
            a.setData(ROLE_OP, True)
            grey = QColor(128, 128, 128)
            a.setForeground(grey)
            v.setForeground(grey)
        self.table.setItem(row, 0, a)
        self.table.setItem(row, 1, v)
        return row

    def _on_double_click(self, item):
        """Doppelklick auf userPassword öffnet den Passwort-Dialog."""
        row = item.row()
        attr = self.table.item(row, 0)
        if attr is None or attr.data(ROLE_OP) or attr.text().lower() != "userpassword":
            return
        if self.read_only:
            self.status("Nur-Lesen-Modus: Passwort kann nicht geändert werden.")
            return
        self.set_password()

    def _on_item_changed(self, _item):
        if not self._loading:
            self._set_dirty(self._compute_changes() != {})

    def _removable_rows(self) -> list[int]:
        rows = sorted({i.row() for i in self.table.selectedItems()})
        return [r for r in rows if self.table.item(r, 0) is not None
                and not self.table.item(r, 0).data(ROLE_OP)
                and not self.table.item(r, 0).data(ROLE_SEP)]

    def add_value(self):
        if self.current_dn is None or self.read_only:
            return
        preset = ""
        rows = self._removable_rows()
        if rows:
            preset = self.table.item(rows[0], 0).text()
        names = sorted({*self._attr_names, *self.original.keys()}, key=str.lower)
        dlg = AddValueDialog(names, preset, self)
        if not dlg.exec():
            return
        name = dlg.attr.currentText().strip()
        for existing in self.original:  # Schreibweise des Servers übernehmen
            if existing.lower() == name.lower():
                name = existing
        value = dlg.value.text()
        if name.lower() == "userpassword" and not is_hashed(value):
            value = hash_password(value, local_scheme(self.session.profile.password_scheme))
        self._render_rows(self._current_rows() + [(name, value, False)])
        row = self._find_row(name, value)
        if row >= 0:
            self.table.selectRow(row)
            self.table.scrollToItem(self.table.item(row, 1))
        self._set_dirty(self._compute_changes() != {})

    def remove_values(self):
        remove = set(self._removable_rows())
        if not remove:
            return
        keep = [row for row in self._iter_rows() if row[3] not in remove]
        self._render_rows([(n, v, op) for n, v, op, _ in keep])
        self._set_dirty(self._compute_changes() != {})

    def _iter_rows(self):
        """Wie _current_rows, aber mit Tabellenzeile als 4. Element."""
        for r in range(self.table.rowCount()):
            a, v = self.table.item(r, 0), self.table.item(r, 1)
            if a is None or v is None or a.data(ROLE_SEP):
                continue
            raw = get_raw(v)
            yield (a.text(), raw if raw is not None else v.text(), bool(a.data(ROLE_OP)), r)

    def _compute_changes(self) -> dict[str, list]:
        current: dict[str, tuple[str, list]] = {}
        for row in range(self.table.rowCount()):
            a, v = self.table.item(row, 0), self.table.item(row, 1)
            if a is None or v is None or a.data(ROLE_OP) or a.data(ROLE_SEP):
                continue
            name = a.text().strip()
            raw = get_raw(v)
            if raw is not None:
                text = decode_value(name, raw)
                val = raw if text is None else text
            else:
                val = v.text()
            if not name or val == "":
                continue
            current.setdefault(name.lower(), (name, []))[1].append(val)
        orig: dict[str, tuple[str, list]] = {}
        for name, values in self.original.items():
            vals = []
            for raw in values:
                text = decode_value(name, raw)
                vals.append(raw if text is None else text)
            orig[name.lower()] = (name, vals)
        changes = {}
        for key in set(orig) | set(current):
            old = orig.get(key, ("", []))[1]
            new = current.get(key, ("", []))[1]
            if Counter(old) != Counter(new):
                changes[(current.get(key) or orig.get(key))[0]] = new
        return changes

    def save_changes(self) -> bool:
        if self.current_dn is None or self.read_only:
            return False
        changes = self._compute_changes()
        if not changes:
            self._set_dirty(False)
            return True
        if run_safely(self, "Speichern", self.session.modify, self.current_dn, changes) is FAIL:
            return False
        self.status(f"Gespeichert: {', '.join(sorted(changes))}")
        self.load_entry(self.current_dn)
        return True

    def confirm_discard(self) -> bool:
        if not self.dirty:
            return True
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(APP_NAME)
        box.setText(f"Ungespeicherte Änderungen an\n{self.current_dn}")
        box.setStandardButtons(QMessageBox.StandardButton.Save |
                               QMessageBox.StandardButton.Discard |
                               QMessageBox.StandardButton.Cancel)
        box.exec()
        answer = box.standardButton(box.clickedButton())
        if answer == QMessageBox.StandardButton.Save:
            return self.save_changes()
        if answer == QMessageBox.StandardButton.Discard:
            self._set_dirty(False)
            return True
        return False

    # Aktionen ---------------------------------------------------------------------
    def refresh(self):
        if not self.confirm_discard():
            return
        item = self.tree.currentItem()
        if item is None:
            run_safely(self, "Aktualisieren", self.populate_roots)
            return
        self._reload_item(item)
        if self.current_dn is not None:
            self.load_entry(self.current_dn)

    def new_entry(self):
        if self.current_dn is None or not self.confirm_discard():
            return
        dlg = NewEntryDialog(self.current_dn, self.session.object_classes(), self)
        if dlg.exec():
            self._create_from_dialog(dlg)

    # Drag & Drop ------------------------------------------------------------------
    def handle_drop(self, src: str, target: str, mode: str | None):
        if self.read_only or not self.confirm_discard():
            return
        problem = self.session.check_target(src, target)
        if problem:
            QMessageBox.warning(self, APP_NAME, problem)
            return
        same_parent = norm_dn(parent_of(src)) == norm_dn(target)
        if mode is None:
            mode = self._ask_drop_action(src, target, same_parent)
        if mode == "move" and same_parent:
            self.status("Der Eintrag liegt bereits dort.")
        elif mode == "move":
            self._move_to(src, target)
        elif mode == "copy":
            self._copy_to(src, target, same_parent)

    def _ask_drop_action(self, src: str, target: str, same_parent: bool) -> str | None:
        menu = QMenu(self)
        head = menu.addAction(f"{rdn_of(src)}  →  {rdn_of(target)}")
        head.setEnabled(False)
        menu.addSeparator()
        mv = menu.addAction(std_icon(self, "SP_ArrowRight"), "Hierher verschieben\tUmschalt")
        mv.setEnabled(not same_parent)
        cp = menu.addAction(std_icon(self, "SP_FileIcon"), "Hierher kopieren\tStrg")
        menu.addSeparator()
        menu.addAction("Abbrechen")
        chosen = menu.exec(QCursor.pos())
        return "move" if chosen is mv else "copy" if chosen is cp else None

    def _after_change(self, *parents: str, open_dn: str | None = None):
        for dn in parents:
            item = self.find_item(dn)
            if item is not None:
                self._reload_item(item)
                item.setExpanded(True)
        if open_dn:
            self.open_dn(open_dn)

    def _move_to(self, src: str, target: str):
        count = run_safely(self, "Verschieben", lambda: len(self.session.subtree_dns(src)))
        if count is FAIL:
            return
        if count > 1 and QMessageBox.question(
                self, "Verschieben", f"„{rdn_of(src)}“ mit allen {count - 1} Untereinträgen "
                                     f"nach\n{target}\nverschieben?") != QMessageBox.StandardButton.Yes:
            return
        try:
            with busy():
                result = self.session.move_entry(src, target)
        except NonLeafMoveError:
            if QMessageBox.question(
                    self, "Verschieben",
                    "Der Server erlaubt nicht, Einträge mit Untereinträgen direkt zu verschieben.\n\n"
                    f"Stattdessen alle {count} Einträge kopieren und die Originale löschen?") \
                    != QMessageBox.StandardButton.Yes:
                return
            result = run_safely(self, "Verschieben", self.session.move_entry, src, target, True)
            if result is FAIL:
                self._after_change(parent_of(src), target)
                return
        except (LdapError, LDAPException) as exc:
            QMessageBox.critical(self, "Verschieben", str(exc))
            return
        self._after_change(parent_of(src), target, open_dn=result["new_dn"])
        refs = f", {result['refs']} Gruppenverweis(e) angepasst" if result["refs"] else ""
        self.status(f"Verschoben nach {target}{refs}", 8000)

    def _copy_to(self, src: str, target: str, same_parent: bool):
        new_rdn = None
        if same_parent:
            attr, value = rdn_of(src).split("=", 1)
            new_rdn, ok = QInputDialog.getText(
                self, "Kopieren", "Am selben Ort wird ein neuer Name (RDN) benötigt:",
                QLineEdit.EchoMode.Normal, f"{attr}={value}-kopie")
            if not ok or "=" not in new_rdn or not new_rdn.split("=", 1)[1].strip():
                return
        count = run_safely(self, "Kopieren", lambda: len(self.session.subtree_dns(src)))
        if count is FAIL:
            return
        if count > 1 and QMessageBox.question(
                self, "Kopieren", f"„{rdn_of(src)}“ mit allen {count - 1} Untereinträgen nach\n"
                                  f"{target}\nkopieren?") != QMessageBox.StandardButton.Yes:
            return

        def progress(i, total, _dn):
            if i % 20 == 0 or i == total:
                self.status(f"Kopiere … {i}/{total}")
                QApplication.processEvents()

        created = run_safely(self, "Kopieren", self.session.copy_subtree, src, target,
                             progress, new_rdn)
        if created is FAIL:
            self._after_change(target)
            return
        self._after_change(target, open_dn=created[0])
        self.status(f"{len(created)} Eintrag/Einträge nach {target} kopiert", 8000)

    def duplicate_entry(self):
        """Neuer Eintrag auf Basis des ausgewählten Eintrags."""
        dn = self.current_dn
        if dn is None or not self.confirm_discard():
            return
        tpl = run_safely(self, "Duplizieren", self.session.copy_template, dn)
        if tpl is FAIL:
            return
        groups = []
        if self._entry_kind() == "user":
            groups = run_safely(self, "Duplizieren", self.session.groups_of, dn)
            if groups is FAIL:
                groups = []
        dlg = NewEntryDialog(tpl["parent"], self.session.object_classes(), self,
                             copy=tpl, group_count=len(groups))
        if not dlg.exec() or not self._create_from_dialog(dlg):
            return
        if groups and dlg.copy_groups.isChecked():
            errors = []
            with busy():
                for g in groups:
                    try:
                        self.session.add_to_group(g["dn"], dlg.result_dn)
                    except (LdapError, LDAPException) as exc:
                        errors.append(f"{g['label']}: {str(exc).splitlines()[0]}")
            if errors:
                QMessageBox.warning(self, "Duplizieren", "Eintrag angelegt, aber nicht allen "
                                    "Gruppen hinzugefügt:\n\n" + "\n".join(errors))
            self.status(f"Angelegt: {dlg.result_dn} – in {len(groups) - len(errors)} "
                        f"Gruppe(n) aufgenommen")

    def _create_from_dialog(self, dlg: NewEntryDialog) -> bool:
        scheme = local_scheme(self.session.profile.password_scheme)
        for key in list(dlg.result_attrs):
            if key.lower() == "userpassword":
                dlg.result_attrs[key] = [v if is_hashed(v) else hash_password(v, scheme)
                                         for v in dlg.result_attrs[key]]
        if run_safely(self, "Neuer Eintrag", self.session.add, dlg.result_dn,
                      dlg.result_classes, dlg.result_attrs) is FAIL:
            return False
        parent_item = self.find_item(parent_of(dlg.result_dn))
        if parent_item is not None:
            self._reload_item(parent_item)
            parent_item.setExpanded(True)
        self.open_dn(dlg.result_dn)
        self.status(f"Angelegt: {dlg.result_dn}")
        return True

    def delete_entry(self):
        dn = self.current_dn
        if dn is None:
            return
        has_children = run_safely(self, "Löschen", self.session.has_children, dn)
        if has_children is FAIL:
            return
        recursive = False
        if has_children:
            dns = run_safely(self, "Löschen", self.session.subtree_dns, dn)
            if dns is FAIL:
                return
            text = (f"„{rdn_of(dn)}“ hat Untereinträge.\n\n"
                    f"Den Eintrag und ALLE {len(dns) - 1} Untereinträge endgültig löschen?")
            recursive = True
        else:
            text = f"Eintrag endgültig löschen?\n\n{dn}"
        box = QMessageBox(QMessageBox.Icon.Warning, "Löschen", text,
                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, self)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.standardButton(box.clickedButton()) != QMessageBox.StandardButton.Yes:
            return
        count = run_safely(self, "Löschen", self.session.delete, dn, recursive)
        if count is FAIL:
            self._reload_item(self.find_item(parent_of(dn)))
            return
        self._set_dirty(False)
        item = self.find_item(dn)
        parent = item.parent() if item is not None else None
        if item is not None:
            (parent.removeChild(item) if parent else
             self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item)))
        if parent is not None and parent.childCount() == 0:
            self._set_expandable(parent, False)
        self.current_dn = None
        self.original = {}
        self.dn_edit.clear()
        self.table.setRowCount(0)
        if parent is not None:
            self.tree.setCurrentItem(parent)
        self._update_actions()
        self.status(f"{count} Eintrag/Einträge gelöscht.")

    def rename_entry(self):
        dn = self.current_dn
        if dn is None or not self.confirm_discard():
            return
        dlg = RenameDialog(dn, self)
        if not dlg.exec():
            return
        new_rdn = dlg.rdn.text().strip()
        new_parent = dlg.new_parent()
        if norm_dn(new_rdn) == norm_dn(rdn_of(dn)) and new_parent is None:
            return
        new_dn = run_safely(self, "Umbenennen", self.session.rename, dn, new_rdn, new_parent,
                            dlg.delete_old.isChecked())
        if new_dn is FAIL:
            return
        self._reload_item(self.find_item(parent_of(dn)))
        if new_parent is not None:
            self._reload_item(self.find_item(new_parent))
        self.open_dn(new_dn)
        self.status(f"Neuer DN: {new_dn}")

    def set_password(self):
        dn = self.current_dn
        if dn is None:
            return
        dlg = PasswordDialog(dn, self.session.profile.password_scheme, self)
        if not dlg.exec():
            return
        pw = dlg.pw1.text()
        scheme = dlg.scheme.currentData()
        if scheme == "server":
            ok = run_safely(self, "Passwort", self.session.password_modify, dn, pw)
            if ok is FAIL:
                return
            if ok:
                self.status("Passwort über den Server geändert.")
                self.load_entry(dn)
                return
            answer = QMessageBox.question(
                self, "Passwort",
                "Der Server unterstützt die Passwort-Änderungsoperation (RFC 3062) nicht "
                "oder hat sie abgelehnt.\n\nStattdessen einen {SSHA512}-Hash erzeugen und "
                "direkt in userPassword speichern?")
            if answer != QMessageBox.StandardButton.Yes:
                return
            scheme = "SSHA512"
        stored = run_safely(self, "Passwort", self.session.set_user_password_attr, dn, pw, scheme)
        if stored is FAIL:
            return
        label = "im Klartext" if scheme == "plain" else f"als {{{scheme}}}-Hash"
        self.status(f"Passwort {label} gespeichert.")
        self.load_entry(dn)

    def manage_groups(self):
        dn = self.current_dn
        kind = self._entry_kind()
        if dn is None or kind is None or not self.confirm_discard():
            return
        if kind == "group":
            res = run_safely(self, "Mitglieder", self.session.group_members, dn)
            if res is FAIL:
                return
            attr, member_kind, members = res
            dlg = GroupMembersDialog(self, dn, attr, member_kind, members)
        else:
            groups = run_safely(self, "Gruppen", self.session.groups_of, dn)
            if groups is FAIL:
                return
            dlg = UserGroupsDialog(self, dn, groups)
        if dlg.exec():
            self.status("Gruppenzuordnung gespeichert.")
            self.load_entry(dn)

    def import_ldif(self):
        if not self.confirm_discard():
            return
        dlg = ImportDialog(self)
        dlg.exec()
        if dlg.imported:
            run_safely(self, "Aktualisieren", self.populate_roots)

    def open_search(self):
        base = self.current_dn if self.current_dn is not None else (self.session.roots() or [""])[0]
        dlg = SearchDialog(self, base)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._search_dialogs.append(dlg)
        dlg.destroyed.connect(lambda *_: self._search_dialogs.remove(dlg)
                              if dlg in self._search_dialogs else None)
        dlg.show()

    def export_ldif(self):
        dn = self.current_dn
        if dn is None:
            return
        default = (rdn_of(dn).split("=", 1)[-1] or "export").replace(" ", "_") + ".ldif"
        path, _ = QFileDialog.getSaveFileName(self, "LDIF exportieren", default,
                                              "LDIF (*.ldif);;Alle Dateien (*)")
        if not path:
            return
        count = run_safely(self, "LDIF-Export", self.session.export_ldif, dn, path)
        if count is not FAIL:
            self.status(f"{count} Einträge exportiert nach {path}", 10000)

    def server_info(self):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Server-Info – {self.session.profile.name}")
        dlg.resize(720, 560)
        text = QPlainTextEdit(self.session.server_info_text())
        text.setReadOnly(True)
        mono = QFont("Menlo" if sys.platform == "darwin" else "Monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        text.setFont(mono)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        layout = QVBoxLayout(dlg)
        layout.addWidget(text)
        layout.addWidget(buttons)
        dlg.exec()

    def close_session(self):
        for dlg in list(self._search_dialogs):
            dlg.close()
        self.session.close()


# =========================================================================== #
# Hauptfenster
# =========================================================================== #
class MainWindow(QMainWindow):
    def __init__(self, store: ProfileStore):
        super().__init__()
        self.store = store
        self.toolbar_style = str(settings().value("toolbar_style", "compact"))
        if self.toolbar_style not in {k for k, _ in TOOLBAR_STYLES}:
            self.toolbar_style = "compact"
        self.setWindowTitle(APP_NAME)
        self.resize(1200, 760)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)

        welcome = QWidget()
        wl = QVBoxLayout(welcome)
        wl.addStretch()
        title = QLabel(APP_NAME)
        f = title.font()
        f.setPointSize(f.pointSize() + 10)
        f.setBold(True)
        title.setFont(f)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub = QLabel("Verwalte LDAP-Verzeichnisse – OpenLDAP, 389 DS, Active Directory und mehr.")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        b1 = QPushButton(std_icon(self, "SP_DriveNetIcon"), "  Verbindungen verwalten…")
        b1.clicked.connect(self.manage_connections)
        b2 = QPushButton("  Demo-Server ausprobieren")
        b2.clicked.connect(self.open_demo)
        self.quick = QListWidget()
        self.quick.setMaximumHeight(220)
        self.quick.itemDoubleClicked.connect(self._quick_connect)
        for w in (b1, b2):
            w.setMinimumWidth(260)
        for w in (title, sub):
            wl.addWidget(w)
        wl.addSpacing(18)
        for w in (b1, b2):
            wl.addWidget(w, 0, Qt.AlignmentFlag.AlignCenter)
        wl.addSpacing(12)
        self.quick_label = QLabel("Zuletzt gespeicherte Verbindungen (Doppelklick zum Verbinden):")
        self.quick_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        wl.addWidget(self.quick_label)
        wl.addWidget(self.quick, 0, Qt.AlignmentFlag.AlignCenter)
        wl.addStretch()

        self.stack = QStackedWidget()
        self.stack.addWidget(welcome)
        self.stack.addWidget(self.tabs)
        self.setCentralWidget(self.stack)
        self._build_menu()
        self._refresh_quick()
        self.statusBar().showMessage("Bereit")

    def _build_menu(self):
        m = self.menuBar().addMenu("&Verbindung")
        a = m.addAction("Verbindungen verwalten…")
        a.setShortcut(QKeySequence("Ctrl+O"))
        a.triggered.connect(self.manage_connections)
        self.recent_menu = m.addMenu("Verbinden mit")
        self.recent_menu.aboutToShow.connect(self._fill_recent_menu)
        m.addAction("Demo-Server öffnen").triggered.connect(self.open_demo)
        m.addSeparator()
        a = m.addAction("Abmelden (aktuelle Verbindung)")
        a.setShortcut(QKeySequence("Ctrl+W"))
        a.triggered.connect(lambda *_: self.tabs.count() and self.close_tab(self.tabs.currentIndex()))
        m.addAction("Von allen Servern abmelden").triggered.connect(self.logout_all)
        m.addSeparator()
        a = m.addAction("Beenden")
        a.setShortcut(QKeySequence.StandardKey.Quit)
        a.setMenuRole(QAction.MenuRole.QuitRole)
        a.triggered.connect(self.close)
        v = self.menuBar().addMenu("&Ansicht")
        tb_menu = v.addMenu("Werkzeugleiste")
        group = QActionGroup(self)
        group.setExclusive(True)
        for key, label in TOOLBAR_STYLES:
            a = tb_menu.addAction(label)
            a.setCheckable(True)
            a.setChecked(key == self.toolbar_style)
            group.addAction(a)
            a.triggered.connect(lambda *_, k=key: self.set_toolbar_style(k))
        h = self.menuBar().addMenu("&Hilfe")
        a = h.addAction(f"Über {APP_NAME}")
        a.setMenuRole(QAction.MenuRole.AboutRole)
        a.triggered.connect(self.about)

    def _fill_recent_menu(self):
        self.recent_menu.clear()
        if not self.store.profiles:
            self.recent_menu.addAction("(keine gespeicherten Verbindungen)").setEnabled(False)
        for p in self.store.profiles:
            self.recent_menu.addAction(f"{p.name}  –  {p.url()}").triggered.connect(
                lambda _=False, prof=p: self.connect_profile(prof))

    def _refresh_quick(self):
        self.quick.clear()
        for p in self.store.profiles:
            item = QListWidgetItem(std_icon(self, "SP_DriveNetIcon"), f"{p.name}   ({p.url()})")
            item.setData(ROLE_DN, p.id)
            self.quick.addItem(item)
        visible = bool(self.store.profiles)
        self.quick.setVisible(visible)
        self.quick_label.setVisible(visible)
        if visible:
            self.quick.setFixedWidth(fit_list_width(self.quick, 360))

    def _quick_connect(self, item):
        pid = item.data(ROLE_DN)
        for p in self.store.profiles:
            if p.id == pid:
                self.connect_profile(p)

    def manage_connections(self):
        dlg = ConnectionManagerDialog(self.store, self)
        accepted = dlg.exec()
        self._refresh_quick()
        if accepted and dlg.selected:
            self.connect_profile(dlg.selected)

    def connect_profile(self, profile: Profile):
        password = None
        if profile.auth == "simple":
            password = self.store.get_password(profile)
            if password is None:
                password, ok = QInputDialog.getText(
                    self, f"Anmelden – {profile.name}",
                    f"Passwort für\n{profile.bind_dn or '(kein Bind-DN)'}:",
                    QLineEdit.EchoMode.Password)
                if not ok:
                    return
        session = run_safely(self, f"Verbinden – {profile.name}", LdapSession.open, profile, password)
        if session is not FAIL:
            self.add_session(session)

    def open_demo(self):
        session = run_safely(self, "Demo-Server", demo_session)
        if session is not FAIL:
            self.add_session(session)

    def set_toolbar_style(self, mode: str):
        self.toolbar_style = mode
        settings().setValue("toolbar_style", mode)
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, SessionWidget):
                apply_toolbar_style(w.toolbar, mode)

    def add_session(self, session: LdapSession):
        widget = SessionWidget(session, self)
        title = session.profile.name
        idx = self.tabs.addTab(widget, std_icon(self, "SP_DriveNetIcon"), title)
        self.tabs.setTabToolTip(idx, f"{session.profile.url()}\n{session.profile.bind_dn or 'anonym'}")
        self.tabs.setCurrentIndex(idx)
        self.stack.setCurrentWidget(self.tabs)
        self.statusBar().showMessage(f"Verbunden mit {session.profile.url()}", 5000)

    def close_tab(self, index: int):
        widget = self.tabs.widget(index)
        if isinstance(widget, SessionWidget):
            if not widget.confirm_discard():
                return
            widget.close_session()
            self.statusBar().showMessage(
                f"Abgemeldet von {widget.session.profile.name} ({widget.session.profile.url()})", 6000)
        self.tabs.removeTab(index)
        if widget is not None:
            widget.deleteLater()
        if self.tabs.count() == 0:
            self._refresh_quick()
            self.stack.setCurrentIndex(0)

    def logout_all(self):
        for i in reversed(range(self.tabs.count())):
            before = self.tabs.count()
            self.close_tab(i)
            if self.tabs.count() == before:  # Abmelden wegen ungespeicherter Änderungen abgebrochen
                return

    def closeEvent(self, event):
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, SessionWidget) and not w.confirm_discard():
                event.ignore()
                return
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, SessionWidget):
                w.close_session()
        event.accept()

    def about(self):
        QMessageBox.about(self, f"Über {APP_NAME}",
                          f"<b>{APP_NAME} {APP_VERSION}</b><br>"
                          "LDAP-Verwaltung für macOS und Linux.<br><br>"
                          f"Profile: {self.store.path}<br>"
                          "Passwörter: System-Schlüsselbund (optional)")


def install_error_dialog():
    """Unerwartete Fehler als Fenster zeigen – wichtig, wenn die App ohne Terminal läuft.
    Der vollständige Traceback landet zusätzlich im Log (stderr)."""
    import traceback

    def hook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        sys.stderr.write(text)
        sys.stderr.flush()
        try:
            box = QMessageBox(QMessageBox.Icon.Critical, APP_NAME,
                              f"Unerwarteter Fehler: {exc}")
            box.setDetailedText(text)
            box.exec()
        except Exception:
            pass

    sys.excepthook = hook


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setOrganizationName("ldap-admin")
    app.setDesktopFileName("ldap-admin")      # Zuordnung zum Menüeintrag (KDE/Wayland)
    install_error_dialog()
    window = MainWindow(ProfileStore())
    window.show()
    if "--demo" in sys.argv:
        window.open_demo()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
