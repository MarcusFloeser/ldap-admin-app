# LDAP Admin – Projektübersicht

Grafische LDAP-Verwaltung für **macOS und Linux** (Hauptsystem: Fedora mit KDE Plasma).
Python 3 + **PySide6** (Qt 6) für die Oberfläche, **ldap3** für LDAP, **keyring** für
Passwörter im System-Schlüsselbund. Aktuelle Version: **1.12**.

## Dateien

| Datei | Inhalt |
|---|---|
| `ldap_admin.py` | Oberfläche (Qt): Hauptfenster, Tabs pro Verbindung, alle Dialoge |
| `ldap_backend.py` | Ohne GUI: Profile, Schlüsselbund, LDAP-Operationen, LDIF, Hashing, Demo-Server |
| `start.sh` | Start/Einrichtung (venv), `--detach`, `--demo`, `--setup`, `--check`, Log ohne Terminal |
| `install-linux-menu.sh` | KDE/GNOME-Menüeintrag (startet ohne Terminal), `--desktop`, `--remove` |
| `install-macos-app.sh` | Eigenständige `LDAP Admin.app` in ~/Applications, richtet Python gleich ein |
| `requirements.txt` | PySide6, ldap3, keyring |
| `README.md` | Anleitung für Anwender |

## Aufbau `ldap_backend.py`

- `Profile` (Dataclass) + `ProfileStore` – JSON in `~/.config/ldap-admin/` bzw.
  `~/Library/Application Support/LDAP-Admin/`; Passwörter nur im Schlüsselbund.
  Export/Import: `export_profiles`, `read_export` → `ExportFile`, `import_profiles`
  (skip/replace/copy, Passwörter vorab entschlüsselt), `find_existing`.
  Passwort-Verschlüsselung nur mit Standardbibliothek: PBKDF2-SHA256 → HMAC-SHA256-CTR
  + HMAC (Encrypt-then-MAC), Prüfwert `check` in `encryption`.
- `LdapSession` – kapselt `ldap3.Connection` (`raise_exceptions=False`, Fehler über
  `_check()` → `LdapError`). Wichtige Methoden: `open`, `search` (Paged Results mit
  Rückfall), `children_info` (mit `hasSubordinates`), `read` (Rohbytes), `modify`
  (REPLACE), `add`, `delete` (rekursiv), `rename`, `move_entry`, `copy_subtree`,
  `update_references`, Gruppen (`group_members`, `set_group_members`, `groups_of`,
  `add_to_group`, `remove_from_group`, `find_entries`), `copy_template`, `next_free_id`,
  `password_modify` / `set_user_password_attr`, `import_records`, `export_ldif`.
- `known_attrs` / `known_classes` – ldap3 prüft Namen streng gegen das Server-Schema;
  Filter nur mit bekannten Attributen/Klassen bauen (z. B. kein `sAMAccountName` bei OpenLDAP).
- Suchfilter: `condition_filter(attr, op, value)`, `build_filter(conditions, "and"|"or")`,
  `FILTER_OPS`, `OPS_WITHOUT_VALUE`, `FREQUENT_ATTRS`; `*` im Wert bleibt Platzhalter,
  Rest wird mit `escape_filter_chars` maskiert.
- Hilfsfunktionen: `hash_password` ({SSHA}/{SSHA256}/{SSHA512}, Großbuchstaben-Schema),
  `verify_password`, `parse_ldif` (RFC 2849), `ldif_line`, DN-Helfer (`split_dn`,
  `rdn_of`, `parent_of`, `norm_dn`), `decode_value` (Binärerkennung).
- `demo_session()` – Offline-Server mit ldap3 `MOCK_SYNC` (dc=example,dc=org).
  Einschränkung: verschiebt keine Teilbäume per modrdn und ignoriert neue RDNs mit newSuperior.

## Aufbau `ldap_admin.py`

- `MainWindow` – Startseite mit Schnellliste, Tabs, Menüs (Verbindung, Ansicht, Hilfe),
  Werkzeugleisten-Stil (QSettings), Abmelden.
- `SessionWidget` – ein Tab: Werkzeugleiste, `LdapTree` (Drag & Drop), Attributtabelle.
  Tabelle wird immer über `_render_rows` sortiert aufgebaut (objectClass oben,
  Trennzeilen mit `ROLE_SEP`, operative Attribute grau). Änderungen werden als Diff
  gegen `self.original` berechnet (`_compute_changes`) und per REPLACE gespeichert.
- Dialoge: `ConnectionDialog`, `ConnectionManagerDialog`, `ExportConnectionsDialog`,
  `ImportConnectionsDialog` (Helfer `export_connections`, `import_connections`), `NewEntryDialog` (Vorlagen +
  Kopie), `RenameDialog`, `PasswordDialog`, `AddValueDialog`, `GroupMembersDialog`,
  `UserGroupsDialog`, `ImportDialog`, `SearchDialog` (mit `ConditionRow`: Attribut-Combo mit
  QCompleter/MatchContains, Vergleich, Wert; Filter live, manuelles Bearbeiten über `_manual`).
- Mixins/Helfer: `SizeMemory` (Dialoggröße merken), `make_form` (Felder wachsen mit),
  `run_safely` (Fehler als Dialog, gibt `FAIL` zurück), `Raw` (Rohbytes in Item-Daten,
  damit PySide6 sie nicht in QByteArray umwandelt).

## Konventionen

- Oberfläche und Meldungen auf **Deutsch**.
- PySide6-Enums immer voll qualifiziert (`Qt.ItemFlag.ItemIsEditable`).
- `QMessageBox.exec()` liefert int → `box.standardButton(box.clickedButton())` vergleichen.
- Signal-Lambdas als `lambda *_: …` und Slots als `def x(self, *_)` (Qt übergibt teils
  `checked`).
- Passwörter nie im Klartext anzeigen oder ungefragt speichern; Standard je Profil
  (`password_scheme`).
- `start.sh` muss mit bash 3.2 (macOS) laufen: keine Bash-4-Funktionen.

## Versionsverlauf

| Version | Änderungen |
|---|---|
| 1.0 | Grundversion: Profile, TLS, Baum, Attribute, Suche, LDIF-Export, Demo-Server |
| 1.1 | LDIF-Import, Gruppenverwaltung, Passwort-Hashing |
| 1.2 | Abmelden-Knopf, Verbindungsliste passt sich an |
| 1.3 | Kompakte Werkzeugleiste, Menü Ansicht |
| 1.4 | Passwort per Doppelklick, Einträge duplizieren, Kontextmenü |
| 1.5 | Breitere Formularfelder, Dialoggrößen werden gespeichert |
| 1.6 | Drag & Drop (verschieben/kopieren, Teilbäume, Gruppenverweise) |
| 1.7 | Attribute alphabetisch sortiert, Trennlinie nach objectClass |
| 1.8 | Aufklapp-Pfeile nur bei Einträgen mit Untereinträgen |
| 1.9 | Start ohne Terminal (Menüeintrag, macOS-App, `--detach`), Fehlerdialog |
| 1.10 | Eigenständige macOS-App, `--check`, Python-Versionsfallback |
| 1.11 | Export/Import der Verbindungen, Passwörter optional verschlüsselt |
| 1.12 | Suche mit Bedingungen: Attribut mit Vorschlägen, Vergleich, Wert, UND/ODER |

## Offen / Ideen

- macOS-App auf echtem Mac bestätigen (bisher nur simuliert getestet).
- Active Directory: Passwörter über `unicodePwd` statt `userPassword`.
