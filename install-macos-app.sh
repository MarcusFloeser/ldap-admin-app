#!/usr/bin/env bash
# Legt "LDAP Admin.app" in ~/Programme (~/Applications) an – eigenständig:
# Das Programm wird in die App kopiert und die Python-Umgebung gleich eingerichtet.
# Danach per Doppelklick, Launchpad, Spotlight oder Dock startbar – ohne Terminal.
#
#   ./install-macos-app.sh           App anlegen bzw. aktualisieren
#   ./install-macos-app.sh --remove  App entfernen
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/Applications/LDAP Admin.app"
RES="$APP/Contents/Resources/ldap-admin"

if [ "$(uname)" != "Darwin" ]; then
  echo "Dieses Skript ist für macOS. Unter Linux: ./install-linux-menu.sh"
  exit 1
fi
if [ "${1:-}" = "--remove" ]; then
  rm -rf "$APP"
  echo "App entfernt."
  exit 0
fi

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# Vorhandene Python-Umgebung bei einer Aktualisierung behalten
KEEP=""
if [ -d "$RES/.venv" ]; then
  KEEP="$(mktemp -d)"
  mv "$RES/.venv" "$KEEP/.venv"
fi
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$RES"

# Programm in die App kopieren (macOS erlaubt Apps keinen stillen Zugriff auf
# Downloads/Schreibtisch/Dokumente – deshalb nicht von dort starten)
for f in ldap_admin.py ldap_backend.py start.sh requirements.txt README.md; do
  cp "$SRC/$f" "$RES/"
done
chmod +x "$RES/start.sh"
if [ -n "$KEEP" ]; then
  mv "$KEEP/.venv" "$RES/.venv"
  rmdir "$KEEP"
fi

cat > "$APP/Contents/MacOS/LDAP Admin" <<'EOF'
#!/bin/bash
HERE="$(cd "$(dirname "$0")/../Resources/ldap-admin" && pwd)"
exec "$HERE/start.sh" "$@"
EOF
chmod +x "$APP/Contents/MacOS/LDAP Admin"

cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>LDAP Admin</string>
  <key>CFBundleDisplayName</key><string>LDAP Admin</string>
  <key>CFBundleExecutable</key><string>LDAP Admin</string>
  <key>CFBundleIdentifier</key><string>local.ldap-admin</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.10</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

ICON_SRC="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericNetworkIcon.icns"
if [ -f "$ICON_SRC" ]; then cp "$ICON_SRC" "$APP/Contents/Resources/AppIcon.icns"; fi

# Download-Sperre (Quarantäne) entfernen, die beim Entpacken übernommen wurde
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

echo "Richte Python-Umgebung ein …"
if ! LDAP_ADMIN_INTERACTIVE=1 "$RES/start.sh" --setup; then
  echo
  echo "Die Einrichtung ist fehlgeschlagen (siehe oben). Die App wurde trotzdem angelegt;"
  echo "nach dem Beheben einfach dieses Skript erneut ausführen."
  exit 1
fi

touch "$APP"
LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [ -x "$LSREG" ]; then "$LSREG" -f "$APP" >/dev/null 2>&1 || true; fi

echo
echo "Fertig: $APP"
echo "Start: Doppelklick im Ordner „Programme“ (Benutzer), Launchpad oder Spotlight."
echo "Nach einem Update der Dateien dieses Skript einfach erneut ausführen."
