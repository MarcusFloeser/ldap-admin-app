#!/usr/bin/env bash
# Startet LDAP Admin auf macOS und Linux.
# Nutzt vorhandene System-Pakete, sonst wird einmalig eine virtuelle Umgebung (.venv) angelegt.
#
#   ./start.sh            im Vordergrund (Meldungen im Terminal)
#   ./start.sh --detach   im Hintergrund – das Terminal kann danach geschlossen werden
#   ./start.sh --demo     mit Offline-Demo-Server
#   ./start.sh --setup    nur die Python-Umgebung einrichten, nicht starten
#   ./start.sh --check    Diagnose: Python, Pakete, Log anzeigen
#
# Ohne Terminal (Menüeintrag, macOS-App) landen Meldungen in einer Logdatei.
# Hinweis: bewusst kompatibel mit bash 3.2 (Standard unter macOS).
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(uname)" = "Darwin" ]; then
  LOG="$HOME/Library/Logs/LDAP-Admin.log"
else
  LOG="${XDG_STATE_HOME:-$HOME/.local/state}/ldap-admin/ldap-admin.log"
fi
mkdir -p "$(dirname "$LOG")"

notify() {  # Desktop-Benachrichtigung, falls kein Terminal da ist
  if command -v notify-send >/dev/null 2>&1; then
    notify-send -a "LDAP Admin" -i network-server-database "LDAP Admin" "$1" || true
  elif command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$1\" with title \"LDAP Admin\"" >/dev/null 2>&1 || true
  fi
}

# Argumente auswerten (ohne Bash-4-Funktionen)
DETACH=0; SETUP_ONLY=0; CHECK=0; PASS=""
for a in "$@"; do
  case "$a" in
    --detach|-d) DETACH=1 ;;
    --setup) SETUP_ONLY=1 ;;
    --check) CHECK=1 ;;
    *) PASS="$PASS $a" ;;
  esac
done

# Ohne Terminal (Finder, Menü): Ausgaben ins Log, Fehler als Benachrichtigung.
# Als interaktiv gilt: Terminal an Ein- oder Ausgabe, --check, oder LDAP_ADMIN_INTERACTIVE=1.
INTERACTIVE=1
if [ "$CHECK" = 0 ] && [ "${LDAP_ADMIN_INTERACTIVE:-0}" != 1 ] && [ ! -t 0 ] && [ ! -t 1 ]; then
  INTERACTIVE=0
  exec >>"$LOG" 2>&1
  echo "=== $(date '+%Y-%m-%d %H:%M:%S') Start aus $DIR ==="
  trap 'notify "Start fehlgeschlagen – Details im Log: $LOG"' ERR
fi

fail() {
  echo "$1"
  if [ "$INTERACTIVE" = 0 ]; then notify "$1 – Details: $LOG"; fi
  exit 1
}

cd "$DIR" || fail "Kein Zugriff auf $DIR (macOS: Ordner nicht in Downloads/Schreibtisch/Dokumente ablegen oder ./install-macos-app.sh verwenden)."

# Homebrew & Co. – Finder/Menü-Starts haben oft einen sehr knappen PATH
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if [ "$DETACH" = 1 ]; then
  # shellcheck disable=SC2086
  if command -v setsid >/dev/null 2>&1; then
    setsid "$DIR/start.sh" $PASS </dev/null >>"$LOG" 2>&1 &
  else
    nohup "$DIR/start.sh" $PASS </dev/null >>"$LOG" 2>&1 &
  fi
  echo "LDAP Admin läuft im Hintergrund (Log: $LOG)"
  exit 0
fi

has_modules() { "$1" -c "import PySide6, ldap3" >/dev/null 2>&1; }

if [ "$CHECK" = 1 ]; then
  echo "System:   $(uname -sr) $(uname -m)"
  echo "Ordner:   $DIR"
  echo "Log:      $LOG"
  for c in ${PYTHON:-python3 python3.13 python3.12 python3.11}; do
    if command -v "$c" >/dev/null 2>&1; then
      v="$("$c" --version 2>&1 || echo 'startet nicht')"
      m="fehlen"; has_modules "$c" && m="vorhanden"
      echo "Python:   $c → $(command -v "$c") ($v), PySide6/ldap3: $m"
    fi
  done
  if [ -x .venv/bin/python ]; then
    m="fehlen"; has_modules .venv/bin/python && m="vorhanden"
    echo "Umgebung: .venv ($(.venv/bin/python --version 2>&1)), PySide6/ldap3: $m"
    .venv/bin/python -c "import PySide6; print('          PySide6', PySide6.__version__)" 2>&1 || true
  else
    echo "Umgebung: .venv noch nicht eingerichtet"
  fi
  if [ -f "$LOG" ]; then echo "--- letzte Log-Zeilen ---"; tail -n 25 "$LOG"; fi
  exit 0
fi

# 1) System-Python hat schon alles (z. B. über dnf installiert)?
PY="${PYTHON:-python3}"
if [ "$SETUP_ONLY" = 0 ] && command -v "$PY" >/dev/null 2>&1 && has_modules "$PY"; then
  # shellcheck disable=SC2086
  exec "$PY" ldap_admin.py $PASS
fi

# 2) Virtuelle Umgebung anlegen bzw. verwenden
make_venv() {
  "$1" -m venv .venv &&
  .venv/bin/python -m pip install --quiet --upgrade pip &&
  .venv/bin/python -m pip install --quiet -r requirements.txt
}

if [ ! -x .venv/bin/python ] || ! has_modules .venv/bin/python; then
  rm -rf .venv
  echo "Richte die Umgebung ein (einmalig, ca. 1–2 Minuten) …"
  if [ "$INTERACTIVE" = 0 ]; then notify "Wird beim ersten Start eingerichtet – das dauert 1–2 Minuten …"; fi
  OK=0
  for c in ${PYTHON:-python3 python3.13 python3.12 python3.11}; do
    command -v "$c" >/dev/null 2>&1 || continue
    "$c" --version >/dev/null 2>&1 || continue      # z. B. macOS-Platzhalter ohne Xcode-Tools
    echo "  mit $c ($("$c" --version 2>&1)) …"
    if make_venv "$c"; then OK=1; break; fi
    echo "  → mit $c fehlgeschlagen, versuche nächste Python-Version"
    rm -rf .venv
  done
  [ "$OK" = 1 ] || fail "Einrichtung fehlgeschlagen. Python 3.11–3.13 installieren, z. B.:
  macOS:  brew install python@3.12   (oder https://www.python.org)
  Fedora: sudo dnf install python3-pyside6 python3-ldap3 python3-keyring"
  echo "Einrichtung abgeschlossen."
fi

[ "$SETUP_ONLY" = 1 ] && exit 0
# shellcheck disable=SC2086
exec .venv/bin/python ldap_admin.py $PASS
