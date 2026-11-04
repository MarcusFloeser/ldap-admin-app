#!/usr/bin/env bash
# Legt einen Eintrag "LDAP Admin" im Anwendungsmenü an (KDE Plasma, GNOME, …).
# Der Eintrag startet die App ohne Terminalfenster.
#   ./install-linux-menu.sh            Menüeintrag anlegen
#   ./install-linux-menu.sh --desktop  zusätzlich Verknüpfung auf dem Schreibtisch
#   ./install-linux-menu.sh --remove   Menüeintrag (und Verknüpfung) entfernen
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
TARGET="$APPS/ldap-admin.desktop"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"

if [ "${1:-}" = "--remove" ]; then
  rm -f "$TARGET" "$DESKTOP_DIR/ldap-admin.desktop"
  command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" || true
  echo "Menüeintrag entfernt."
  exit 0
fi

mkdir -p "$APPS"
cat > "$TARGET" <<EOF
[Desktop Entry]
Type=Application
Name=LDAP Admin
GenericName=LDAP-Verwaltung
Comment=LDAP-Verzeichnisse verwalten
Exec="$DIR/start.sh"
Path=$DIR
Icon=network-server-database
Terminal=false
StartupNotify=true
Categories=System;Network;Utility;
Keywords=ldap;openldap;directory;verzeichnis;
Actions=demo;

[Desktop Action demo]
Name=Mit Demo-Server starten
Exec="$DIR/start.sh" --demo
EOF
chmod +x "$DIR/start.sh"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" || true
echo "Menüeintrag angelegt: $TARGET"

if [ "${1:-}" = "--desktop" ]; then
  mkdir -p "$DESKTOP_DIR"
  cp "$TARGET" "$DESKTOP_DIR/ldap-admin.desktop"
  chmod +x "$DESKTOP_DIR/ldap-admin.desktop"
  # KDE/GNOME: Verknüpfung als vertrauenswürdig markieren
  command -v gio >/dev/null && gio set "$DESKTOP_DIR/ldap-admin.desktop" metadata::trusted true 2>/dev/null || true
  echo "Verknüpfung auf dem Schreibtisch angelegt."
fi
