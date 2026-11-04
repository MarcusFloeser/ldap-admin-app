# LDAP Admin

Grafische Verwaltungsoberfläche für LDAP-Server – läuft auf **macOS** und **Linux**
(getestet mit OpenLDAP-kompatiblen Verzeichnissen; funktioniert auch mit 389 DS,
FreeIPA und Active Directory).

## Starten

```bash
unzip ldap-admin.zip && cd ldap-admin
chmod +x start.sh
./start.sh              # beim ersten Start wird eine Python-Umgebung eingerichtet
./start.sh --demo       # direkt mit dem Offline-Demo-Server starten
```

Voraussetzung ist Python 3.9 oder neuer.

**Fedora (KDE/GNOME):** Alternativ alles aus den Paketquellen installieren, dann startet die
App ohne virtuelle Umgebung:

```bash
sudo dnf install python3-pyside6 python3-ldap3 python3-keyring
./start.sh
./install-linux-menu.sh   # optional: Eintrag im Anwendungsmenü (startet ohne Terminal)
```

**macOS:** Python über Homebrew (`brew install python`) oder python.org installieren,
dann `./start.sh` im Terminal ausführen.

## Ohne Terminal starten

| System | Einrichtung (einmalig) | Danach starten über |
|---|---|---|
| Linux (KDE, GNOME) | `./install-linux-menu.sh` (mit `--desktop` zusätzlich Schreibtisch-Symbol) | Anwendungsmenü, KRunner, Taskleiste |
| macOS | `./install-macos-app.sh` – kopiert das Programm in die App und richtet Python gleich ein | Programme-Ordner (Benutzer), Launchpad, Spotlight, Dock |
| beide | – | `./start.sh --detach` – Terminal danach schließbar |

Tipp: Den ersten Start einmal im Terminal mit `./start.sh` machen – dann sieht man die
Einrichtung. Ohne Terminal erscheint stattdessen eine Benachrichtigung.

Läuft die App ohne Terminal, schreibt sie Meldungen in ein Log; unerwartete Fehler werden
zusätzlich als Fenster angezeigt:

- Linux: `~/.local/state/ldap-admin/ldap-admin.log`
- macOS: `~/Library/Logs/LDAP-Admin.log` (auch in der App „Konsole“ sichtbar)

Wird der Ordner `ldap-admin` verschoben, das jeweilige Installationsskript einfach erneut
ausführen. Entfernen mit `--remove`.

## Funktionen

- **Mehrere Verbindungsprofile** – Server, Port, Bind-DN, Basis-DN, Timeout, Seitengröße
- **Verschlüsselung:** unverschlüsselt, StartTLS oder LDAPS; Zertifikatsprüfung mit
  System-Zertifikaten oder eigener CA-Datei
- **Passwörter** optional im System-Schlüsselbund (macOS-Schlüsselbund, KWallet,
  GNOME-Schlüsselbund) – nie im Klartext in der Konfigurationsdatei
- **Mehrere Verbindungen gleichzeitig** in Tabs; **Abmelden** über den Knopf rechts in der
  Werkzeugleiste, Strg/⌘+W oder Menü *Verbindung → Von allen Servern abmelden*
- **Nur-Lesen-Modus** pro Profil für Produktivsysteme
- Verzeichnisbaum mit Nachladen beim Aufklappen (Paged Results für große Verzeichnisse);
  Aufklapp-Pfeile nur bei Einträgen mit Untereinträgen (über `hasSubordinates`)
- Attribute anzeigen und bearbeiten (Doppelklick), Werte hinzufügen/entfernen,
  Binärwerte werden geschützt angezeigt, operative Attribute auf Wunsch
- Attribute und Werte immer alphabetisch sortiert – objectClass oben, durch eine
  Linie von den übrigen Attributen getrennt; neue Werte werden direkt einsortiert
- Einträge anlegen mit Vorlagen (OU, Person, POSIX-Benutzer, Gruppen)
- **Duplizieren:** neuer Eintrag auf Basis eines vorhandenen – Objektklassen und
  gemeinsame Werte (z. B. Shell, gidNumber, Abteilung) werden übernommen, persönliche
  Felder (Name, Mail, Passwort …) geleert, die nächste freie uidNumber/gidNumber
  vorgeschlagen und auf Wunsch die Gruppenzugehörigkeiten mitkopiert
- **Drag & Drop** im Verzeichnisbaum zum Verschieben und Kopieren – siehe unten
- Rechtsklick-Menü im Verzeichnisbaum
- Umbenennen und Verschieben, rekursives Löschen mit Sicherheitsabfrage
- **Gruppenverwaltung:** Mitglieder einer Gruppe suchen, hinzufügen und entfernen –
  oder umgekehrt für einen Benutzer alle Gruppenzugehörigkeiten bearbeiten
  (groupOfNames, groupOfUniqueNames, posixGroup, AD-Gruppen)
- **Benutzerpasswörter gehasht** – siehe unten
- Suche mit LDAP-Filter, frei wählbaren Spalten und CSV-Export
- **LDIF-Import** (RFC 2849 inkl. changetype add/modify/delete/modrdn) mit Testlauf,
  Konfliktbehandlung, Basis-DN-Ersetzung und Protokoll
- LDIF-Export eines Teilbaums, Server-Info (Root DSE)
- Offline-Demo-Server zum gefahrlosen Ausprobieren

## Benutzerpasswörter (userPassword)

Pro Verbindungsprofil wird unter **„Benutzer-Passwörter“** festgelegt, wie Passwörter
gespeichert werden; im Passwort-Dialog lässt es sich im Einzelfall ändern:

| Verfahren | Bedeutung |
|---|---|
| Server entscheidet | Passwortänderung nach RFC 3062 – der Server hasht nach eigener Richtlinie. Unterstützt er das nicht, bietet die App `{SSHA512}` an. |
| `{SSHA512}` (empfohlen) | LDAP Admin erzeugt einen gesalzenen SHA-512-Hash; der Server sieht das Passwort nie im Klartext. |
| `{SSHA256}` / `{SSHA}` | wie oben, für Server ohne SHA-2-Unterstützung `{SSHA}` wählen |
| Klartext | nur auf ausdrückliche Bestätigung |

Gehasht wird überall, wo Passwörter entstehen: „Passwort“-Aktion, neue Einträge
(Vorlagen enthalten `userPassword`), „Wert hinzufügen“ und LDIF-Import (abschaltbar).
In der Attributliste werden Passwörter nur maskiert angezeigt, inklusive Verfahren;
Klartext-Passwörter sind rot markiert. **Doppelklick auf die Passwortzeile** öffnet den
Dialog zum Ändern.

**Hinweis OpenLDAP:** `{SSHA}` versteht jeder OpenLDAP-Server. Für `{SSHA256}`/`{SSHA512}`
muss das Modul `pw-sha2` geladen sein (bei den meisten aktuellen Distributionen der Fall).
Active Directory verwendet `unicodePwd` statt `userPassword` und wird hierüber nicht bedient.

## LDIF-Import

„LDIF-Import“ in der Werkzeugleiste → Datei wählen. Vor dem Import zeigt der Dialog
die Anzahl der Datensätze und Klartext-Passwörter. Optionen:

- **Eintrag existiert:** überspringen, Attribute ersetzen oder als Fehler werten
- **Basis-DN ersetzen:** z. B. `dc=alt,dc=ch` → `dc=neu,dc=ch` beim Umzug zwischen
  Verzeichnissen (wird bei abweichendem Suffix automatisch vorgeschlagen; gilt für DNs
  und DN-Werte wie `member`)
- **Testlauf** prüft die Datei, ohne etwas zu ändern

## Darstellung

Unter **Ansicht → Werkzeugleiste** lässt sich die Größe der Knöpfe wählen:
*Kompakt* (Standard, kleine Symbole mit Text), *Nur Symbole* (Beschriftung als Tooltip)
oder *Groß*. Die Wahl wird gespeichert.

Eingabefelder in Dialogen wachsen mit der Fensterbreite. Jeder Dialog merkt sich
die zuletzt gewählte Größe.

Wirkt die ganze Oberfläche unter Linux zu groß, liegt das meist an der Bildschirm-
skalierung. Sie lässt sich nur für diese App anpassen, z. B. mit
`QT_SCALE_FACTOR=0.9 ./start.sh`.

## Drag & Drop

Einen Eintrag im Baum auf einen anderen ziehen. Beim Loslassen erscheint ein Menü
„Hierher verschieben / Hierher kopieren / Abbrechen“. Abkürzungen:

| beim Loslassen gedrückt | Wirkung |
|---|---|
| Umschalt | sofort verschieben |
| Strg (Linux) / ⌥ (macOS) | sofort kopieren |

- Ganze Teilbäume (z. B. eine OU mit Inhalt) werden mitverschoben bzw. mitkopiert;
  bei mehr als einem Eintrag folgt eine Sicherheitsabfrage.
- Beim Verschieben werden `member`/`uniqueMember`-Verweise in Gruppen auf den neuen DN
  angepasst.
- Erlaubt der Server kein Verschieben von Teilbäumen, bietet die App an, zu kopieren und
  die Originale danach zu löschen.
- Kopieren in denselben Ordner fragt nach einem neuen Namen (z. B. `uid=ben-kopie`).
- Beim Ziehen über einen zugeklappten Eintrag klappt er nach kurzer Zeit auf.
- Im Nur-Lesen-Modus ist Drag & Drop abgeschaltet.

## Tastenkürzel

| Aktion | Kürzel |
|---|---|
| Verbindungen verwalten | Strg/⌘ + O |
| Aktualisieren | F5 |
| Neuer Eintrag | Strg/⌘ + N |
| Duplizieren (neuer Eintrag auf Basis des ausgewählten) | Strg/⌘ + D |
| Umbenennen/Verschieben | F2 |
| Löschen | Entf |
| Suchen | Strg/⌘ + F |
| Gruppen / Mitglieder | Strg/⌘ + G |
| Speichern | Strg/⌘ + S |
| Abmelden (aktuelle Verbindung) | Strg/⌘ + W |

## Beispiel-Profile

| Ziel | Sicherheit | Port | Bind-DN |
|---|---|---|---|
| OpenLDAP | StartTLS | 389 | `cn=admin,dc=firma,dc=ch` |
| OpenLDAP | LDAPS | 636 | `cn=admin,dc=firma,dc=ch` |
| Active Directory | LDAPS | 636 | `admin@firma.ch` |
| FreeIPA | LDAPS | 636 | `uid=admin,cn=users,cn=accounts,dc=firma,dc=ch` |

Beim Active Directory den Basis-DN auf z. B. `dc=firma,dc=ch` setzen und die Seitengröße
bei höchstens 1000 lassen.

## Speicherorte

- macOS: `~/Library/Application Support/LDAP-Admin/connections.json`
- Linux: `~/.config/ldap-admin/connections.json`

## Fehlerbehebung

- **Diagnose:** `./start.sh --check` zeigt Python-Versionen, ob PySide6/ldap3 vorhanden
  sind, und die letzten Log-Zeilen.
- **macOS: App startet nicht:** `./install-macos-app.sh` im Terminal erneut ausführen –
  Fehler bei der Einrichtung werden dort angezeigt. Den Ordner `ldap-admin` nicht direkt
  aus *Downloads*, *Schreibtisch* oder *Dokumente* per Doppelklick starten: macOS sperrt
  Apps dort den Zugriff. Die installierte App enthält eine eigene Kopie und ist davon
  nicht betroffen.
- **macOS: „Python“ fragt nach Entwicklerwerkzeugen:** Python über Homebrew
  (`brew install python@3.12`) oder python.org installieren.

- **Fenster öffnet sich unter Linux nicht (X11):** `sudo dnf install xcb-util-cursor`
- **Zertifikatsfehler:** CA-Zertifikat des Servers im Profil hinterlegen; „Zertifikat prüfen“
  nur zum Testen deaktivieren.
- **„Passwort speichern“ ausgegraut:** Kein Schlüsselbund gefunden; unter KDE muss KWallet
  bzw. der Secret Service aktiv sein.
