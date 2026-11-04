"""
LDAP-Backend für LDAP Admin: Verbindungsprofile, Passwortspeicher und LDAP-Operationen.
Enthält keinen GUI-Code, damit es unabhängig getestet werden kann.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import unquote, urlparse

from ldap3 import (
    ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, ANONYMOUS, BASE, LEVEL,
    MOCK_SYNC, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, NO_ATTRIBUTES, OFFLINE_SLAPD_2_4,
    SIMPLE, SUBTREE, Connection, Server, Tls,
)
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import to_dn

try:  # macOS-Schlüsselbund / KWallet / GNOME-Schlüsselbund
    import keyring
except ImportError:  # pragma: no cover
    keyring = None

KEYRING_SERVICE = "ldap-admin"
CHILD_LIMIT = 5000

# Attribute, die immer als Binärdaten behandelt werden
BINARY_ATTRS = {
    "jpegphoto", "photo", "objectguid", "objectsid", "usercertificate", "cacertificate",
    "certificaterevocationlist", "authorityrevocationlist", "crosscertificatepair",
    "usersmimecertificate", "userpkcs12", "thumbnailphoto", "msexchmailboxguid",
    "audio", "msds-generationid", "logonhours",
}


class LdapError(Exception):
    pass


class NonLeafMoveError(LdapError):
    """Der Server erlaubt das Verschieben von Einträgen mit Untereinträgen nicht."""


# --------------------------------------------------------------------------- #
# Konfiguration
# --------------------------------------------------------------------------- #
def config_dir() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "LDAP-Admin"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "ldap-admin"
    base.mkdir(parents=True, exist_ok=True)
    return base


@dataclass
class Profile:
    name: str = "Neue Verbindung"
    host: str = "localhost"
    port: int = 389
    security: str = "none"          # none | starttls | ldaps
    verify_cert: bool = True
    ca_file: str = ""
    auth: str = "simple"            # simple | anonymous
    bind_dn: str = ""
    save_password: bool = False
    base_dn: str = ""
    read_only: bool = False
    timeout: int = 10
    page_size: int = 500
    password_scheme: str = "server"   # server | SSHA512 | SSHA256 | SSHA | plain
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def url(self) -> str:
        scheme = "ldaps" if self.security == "ldaps" else "ldap"
        return f"{scheme}://{self.host}:{self.port}"


class ProfileStore:
    """Speichert Profile als JSON (ohne Passwörter); Passwörter optional im System-Schlüsselbund."""

    def __init__(self, path: Path | None = None):
        self.path = path or (config_dir() / "connections.json")
        self.profiles: list[Profile] = self._load()

    def _load(self) -> list[Profile]:
        try:
            data = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError):
            backup = self.path.with_suffix(".defekt.json")
            try:
                self.path.replace(backup)
            except OSError:
                pass
            return []
        return [Profile.from_dict(d) for d in data.get("connections", [])]

    def save(self) -> None:
        payload = {"connections": [asdict(p) for p in self.profiles]}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), "utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)

    # Passwörter -------------------------------------------------------------
    @staticmethod
    def keyring_available() -> bool:
        if keyring is None:
            return False
        try:
            from keyring.backends import fail
            return not isinstance(keyring.get_keyring(), fail.Keyring)
        except Exception:
            return False

    def get_password(self, p: Profile) -> str | None:
        if not (p.save_password and self.keyring_available()):
            return None
        try:
            return keyring.get_password(KEYRING_SERVICE, p.id)
        except Exception:
            return None

    def set_password(self, p: Profile, password: str) -> bool:
        if not self.keyring_available():
            return False
        try:
            keyring.set_password(KEYRING_SERVICE, p.id, password)
            return True
        except Exception:
            return False

    def delete_password(self, p: Profile) -> None:
        if not self.keyring_available():
            return
        try:
            keyring.delete_password(KEYRING_SERVICE, p.id)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Hilfsfunktionen
# --------------------------------------------------------------------------- #
def split_dn(dn: str) -> list[str]:
    if not dn:
        return []
    try:
        return to_dn(dn)
    except Exception:
        return [part.strip() for part in dn.split(",")]


def rdn_of(dn: str) -> str:
    parts = split_dn(dn)
    return parts[0] if parts else dn


def parent_of(dn: str) -> str:
    return ",".join(split_dn(dn)[1:])


def norm_dn(dn: str) -> str:
    return ",".join(p.strip().lower() for p in split_dn(dn))


def decode_value(attr: str, raw: bytes) -> str | None:
    """Liefert Text oder None, wenn der Wert binär ist."""
    name = attr.lower()
    if name in BINARY_ATTRS or name.endswith(";binary"):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 32 and c not in "\t\n\r" for c in text):
        return None
    return text


_SAFE_INIT = set(range(0x01, 0x80)) - {0x0A, 0x0D, 0x20, 0x3A, 0x3C}
_SAFE_CHAR = set(range(0x01, 0x80)) - {0x0A, 0x0D}


def ldif_line(attr: str, value: bytes) -> str:
    """Eine LDIF-Zeile nach RFC 2849 (Base64, wenn nötig)."""
    if not value:
        return f"{attr}:"
    safe = value[0] in _SAFE_INIT and value[-1] != 0x20 and all(b in _SAFE_CHAR for b in value)
    if safe:
        return f"{attr}: {value.decode('ascii')}"
    return f"{attr}:: {base64.b64encode(value).decode('ascii')}"


def _as_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


# --------------------------------------------------------------------------- #
# Passwort-Hashes (Format wie slappasswd / RFC 2307)
# --------------------------------------------------------------------------- #
PASSWORD_SCHEMES = [
    ("server", "Server entscheidet (Passwortänderung nach RFC 3062)"),
    ("SSHA512", "{SSHA512} – gesalzenes SHA-512 (empfohlen)"),
    ("SSHA256", "{SSHA256} – gesalzenes SHA-256"),
    ("SSHA", "{SSHA} – gesalzenes SHA-1 (ältere Server)"),
    ("plain", "Klartext (nicht empfohlen)"),
]
_HASHES = {"SSHA": hashlib.sha1, "SSHA256": hashlib.sha256, "SSHA512": hashlib.sha512}


def hash_password(password: str, scheme: str) -> str:
    """Erzeugt einen userPassword-Wert, z. B. {SSHA512}…  'plain' gibt Klartext zurück."""
    scheme = scheme.upper()
    if scheme == "PLAIN":
        return password
    if scheme not in _HASHES:
        raise ValueError(f"Unbekanntes Hash-Verfahren: {scheme}")
    salt = secrets.token_bytes(16 if scheme != "SSHA" else 8)
    digest = _HASHES[scheme](password.encode("utf-8") + salt).digest()
    return "{%s}%s" % (scheme, base64.b64encode(digest + salt).decode("ascii"))


def verify_password(password: str, stored: str) -> bool:
    """Prüft ein Passwort gegen einen {SSHA*}-Wert (für Tests/Kontrolle)."""
    if not stored.startswith("{"):
        return hmac.compare_digest(password, stored)
    scheme, _, payload = stored[1:].partition("}")
    fn = _HASHES.get(scheme.upper())
    if fn is None:
        return False
    raw = base64.b64decode(payload)
    size = fn().digest_size
    digest, salt = raw[:size], raw[size:]
    return hmac.compare_digest(fn(password.encode("utf-8") + salt).digest(), digest)


def is_hashed(value) -> bool:
    text = value.decode("utf-8", "ignore") if isinstance(value, bytes) else str(value)
    return text.startswith("{") and "}" in text[:20]


def local_scheme(profile_scheme: str) -> str:
    """Hash-Verfahren für lokal erzeugte Werte (bei 'server' wird SSHA512 verwendet)."""
    return "SSHA512" if profile_scheme == "server" else profile_scheme


def describe_password(value) -> str:
    text = value.decode("utf-8", "ignore") if isinstance(value, bytes) else str(value)
    if is_hashed(text):
        return f"•••••• (Hash {text[:text.index('}') + 1].upper()})"
    return "•••••• (Klartext!)"


# --------------------------------------------------------------------------- #
# LDIF-Import (RFC 2849)
# --------------------------------------------------------------------------- #
@dataclass
class LdifRecord:
    dn: str
    changetype: str = "add"                         # add | modify | delete | modrdn
    attrs: dict = field(default_factory=dict)       # bei add: {name: [werte]}
    mods: list = field(default_factory=list)        # bei modify: [(op, name, [werte])]
    newrdn: str = ""
    deleteoldrdn: bool = True
    newsuperior: str | None = None
    line: int = 0


def _unfold(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for no, raw in enumerate(text.splitlines(), 1):
        if raw.startswith(" ") and lines:
            lines[-1] = (lines[-1][0], lines[-1][1] + raw[1:])
        else:
            lines.append((no, raw))
    return lines


def _ldif_value(no: int, line: str, base_dir: str | None) -> tuple[str, object]:
    if ":" not in line:
        raise LdapError(f"LDIF Zeile {no}: „attribut: wert“ erwartet:\n{line}")
    name, rest = line.split(":", 1)
    name = name.strip()
    if rest.startswith(":"):
        raw = base64.b64decode(rest[1:].strip())
        try:
            return name, raw.decode("utf-8")
        except UnicodeDecodeError:
            return name, raw
    if rest.startswith("<"):
        url = urlparse(rest[1:].strip())
        if url.scheme not in ("file", ""):
            raise LdapError(f"LDIF Zeile {no}: nur file://-URLs werden unterstützt.")
        path = unquote(url.path)
        if base_dir and not os.path.isabs(path):
            path = os.path.join(base_dir, path)
        with open(path, "rb") as fh:
            return name, fh.read()
    return name, rest.lstrip(" ")


def parse_ldif(text: str, base_dir: str | None = None) -> list[LdifRecord]:
    records: list[LdifRecord] = []
    blocks: list[list[tuple[int, str]]] = [[]]
    for no, line in _unfold(text):
        if line.startswith("#"):
            continue
        if not line.strip():
            if blocks[-1]:
                blocks.append([])
            continue
        blocks[-1].append((no, line))
    for block in blocks:
        if not block:
            continue
        items = [(no, *_ldif_value(no, line, base_dir)) if line.strip() != "-" else (no, "-", "")
                 for no, line in block]
        if items[0][1].lower() == "version":
            items = items[1:]
            if not items:
                continue
        no, key, dn = items[0]
        if key.lower() != "dn":
            raise LdapError(f"LDIF Zeile {no}: „dn:“ erwartet, gefunden „{key}:“.")
        rec = LdifRecord(dn=str(dn).strip(), line=no)
        rest = items[1:]
        while rest and rest[0][1].lower() == "control":
            rest = rest[1:]
        if rest and rest[0][1].lower() == "changetype":
            rec.changetype = str(rest[0][2]).strip().lower()
            rest = rest[1:]
        if rec.changetype == "moddn":
            rec.changetype = "modrdn"
        if rec.changetype == "add":
            for _, name, value in rest:
                if name == "-":
                    continue
                rec.attrs.setdefault(name, []).append(value)
        elif rec.changetype == "modify":
            current = None
            for no2, name, value in rest:
                if name == "-":
                    current = None
                elif current is None:
                    op = name.lower()
                    if op not in ("add", "delete", "replace"):
                        raise LdapError(f"LDIF Zeile {no2}: add/delete/replace erwartet, "
                                        f"gefunden „{name}“.")
                    current = (op, str(value).strip(), [])
                    rec.mods.append(current)
                else:
                    current[2].append(value)
        elif rec.changetype == "modrdn":
            for _, name, value in rest:
                key = name.lower()
                if key == "newrdn":
                    rec.newrdn = str(value).strip()
                elif key == "deleteoldrdn":
                    rec.deleteoldrdn = str(value).strip() == "1"
                elif key == "newsuperior":
                    rec.newsuperior = str(value).strip()
        elif rec.changetype != "delete":
            raise LdapError(f"LDIF Zeile {no}: unbekannter changetype „{rec.changetype}“.")
        records.append(rec)
    return records


def _replace_suffix(value, old: str, new: str):
    if not old or not isinstance(value, str):
        return value
    if value.lower().endswith(old.lower()):
        cut = len(value) - len(old)
        if cut == 0 or value[cut - 1] == ",":
            return value[:cut] + new
    return value


# --------------------------------------------------------------------------- #
# LDAP-Sitzung
# --------------------------------------------------------------------------- #
class LdapSession:
    def __init__(self, profile: Profile, conn: Connection):
        self.profile = profile
        self.conn = conn

    # Verbindung ---------------------------------------------------------------
    @classmethod
    def open(cls, profile: Profile, password: str | None) -> "LdapSession":
        tls = None
        if profile.security in ("ldaps", "starttls"):
            tls = Tls(
                validate=ssl.CERT_REQUIRED if profile.verify_cert else ssl.CERT_NONE,
                ca_certs_file=profile.ca_file or None,
            )
        server = Server(
            profile.host, port=int(profile.port), use_ssl=profile.security == "ldaps",
            tls=tls, get_info=ALL, connect_timeout=int(profile.timeout),
        )
        kwargs = dict(receive_timeout=int(profile.timeout), raise_exceptions=False,
                      read_only=profile.read_only)
        if profile.auth == "anonymous":
            kwargs["authentication"] = ANONYMOUS
        else:
            kwargs.update(user=profile.bind_dn, password=password or "", authentication=SIMPLE)
        conn = Connection(server, **kwargs)
        session = cls(profile, conn)
        try:
            conn.open()
            if profile.security == "starttls" and not conn.start_tls():
                session._check(False, "StartTLS")
            if not conn.bind():
                session._check(False, "Anmeldung (Bind)")
        except LDAPException as exc:
            raise LdapError(f"Verbindung zu {profile.url()} fehlgeschlagen:\n{exc}") from exc
        return session

    def close(self) -> None:
        try:
            self.conn.unbind()
        except Exception:
            pass

    def _check(self, ok: bool, what: str) -> None:
        if ok:
            return
        r = self.conn.result or {}
        desc = r.get("description") or "unbekannter Fehler"
        msg = (r.get("message") or "").strip()
        raise LdapError(f"{what} fehlgeschlagen: {desc}" + (f"\n{msg}" if msg else ""))

    def _code(self) -> int:
        return (self.conn.result or {}).get("result", 0) or 0

    # Info ----------------------------------------------------------------------
    def roots(self) -> list[str]:
        if self.profile.base_dn.strip():
            return [self.profile.base_dn.strip()]
        info = self.conn.server.info
        contexts = [str(c) for c in (info.naming_contexts or [])] if info else []
        return contexts or [""]

    def server_info_text(self) -> str:
        info = self.conn.server.info
        return str(info) if info else "Keine Server-Informationen verfügbar."

    def object_classes(self) -> list[str]:
        schema = self.conn.server.schema
        if not schema:
            return []
        return sorted({str(n) for n in schema.object_classes}, key=str.lower)

    def attribute_names(self) -> list[str]:
        schema = self.conn.server.schema
        if not schema:
            return []
        return sorted({str(n) for n in schema.attribute_types}, key=str.lower)

    # Lesen ---------------------------------------------------------------------
    def search(self, base: str, flt: str, scope=SUBTREE, attributes=NO_ATTRIBUTES,
               limit: int = 0) -> list[dict]:
        """Seitenweise Suche (Paged Results) mit Rückfall auf normale Suche."""
        results: list[dict] = []
        code = 0
        try:
            gen = self.conn.extend.standard.paged_search(
                base, flt, search_scope=scope, attributes=attributes,
                paged_size=int(self.profile.page_size) or 500, generator=True)
            for r in gen:
                if r.get("type") == "searchResEntry":
                    results.append(r)
                    if limit and len(results) >= limit:
                        break
            code = self._code()
        except LDAPException:
            results, code = [], -1
        if results or code in (0, 4):
            return results
        ok = self.conn.search(base, flt, search_scope=scope, attributes=attributes,
                              size_limit=limit or 0)
        if not ok and self._code() not in (0, 4, 32):
            self._check(False, "Suche")
        return [r for r in (self.conn.response or []) if r.get("type") == "searchResEntry"]

    def children(self, dn: str) -> list[str]:
        entries = self.search(dn, "(objectClass=*)", LEVEL, NO_ATTRIBUTES, CHILD_LIMIT)
        own = norm_dn(dn)
        dns = {e["dn"] for e in entries if norm_dn(e["dn"]) != own}
        return sorted(dns, key=lambda d: rdn_of(d).lower())

    # Attribute, über die Server melden, ob ein Eintrag Untereinträge hat
    SUBORDINATE_ATTRS = ["hasSubordinates", "numSubordinates", "msDS-Approx-Immed-Subordinates"]
    LEAF_CHECK_LIMIT = 300

    def children_info(self, dn: str) -> list[tuple[str, bool | None]]:
        """Unterknoten mit der Angabe, ob sie selbst Untereinträge haben.
        Nutzt hasSubordinates & Co.; fehlt das, wird (bis LEAF_CHECK_LIMIT) einzeln geprüft.
        None = unbekannt."""
        wanted = self.known_attrs(self.SUBORDINATE_ATTRS)
        try:
            entries = self.search(dn, "(objectClass=*)", LEVEL, wanted or NO_ATTRIBUTES, CHILD_LIMIT)
        except (LdapError, LDAPException):
            if not wanted:
                raise
            entries = self.search(dn, "(objectClass=*)", LEVEL, NO_ATTRIBUTES, CHILD_LIMIT)
        own = norm_dn(dn)
        result: dict[str, bool | None] = {}
        for e in entries:
            if norm_dn(e["dn"]) == own:
                continue
            raw = {k.lower(): v for k, v in (e.get("raw_attributes") or {}).items()}
            flag: bool | None = None
            if raw.get("hassubordinates"):
                flag = raw["hassubordinates"][0].strip().upper() == b"TRUE"
            else:
                for key in ("numsubordinates", "msds-approx-immed-subordinates"):
                    if raw.get(key):
                        try:
                            flag = int(raw[key][0]) > 0
                        except ValueError:
                            pass
                        break
            result[e["dn"]] = flag
        unknown = [d for d, f in result.items() if f is None]
        if unknown and len(unknown) <= self.LEAF_CHECK_LIMIT:
            for d in unknown:
                try:
                    result[d] = self.has_children(d)
                except LDAPException:
                    pass
        return sorted(result.items(), key=lambda kv: rdn_of(kv[0]).lower())

    def has_children(self, dn: str) -> bool:
        self.conn.search(dn, "(objectClass=*)", search_scope=LEVEL,
                         attributes=NO_ATTRIBUTES, size_limit=2)
        own = norm_dn(dn)
        return any(r.get("type") == "searchResEntry" and norm_dn(r["dn"]) != own
                   for r in (self.conn.response or []))

    def read(self, dn: str, operational: bool = False):
        """Gibt (Benutzerattribute, operative Attribute) als {name: [bytes]} zurück."""
        ok = self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=[ALL_ATTRIBUTES])
        self._check(ok, "Lesen des Eintrags")
        entries = [r for r in self.conn.response if r.get("type") == "searchResEntry"]
        if not entries:
            raise LdapError(f"Eintrag nicht gefunden:\n{dn}")
        user = {k: list(v) for k, v in entries[0]["raw_attributes"].items()}
        op: dict[str, list[bytes]] = {}
        if operational:
            if self.conn.search(dn, "(objectClass=*)", search_scope=BASE,
                                attributes=[ALL_OPERATIONAL_ATTRIBUTES]):
                lower = {k.lower() for k in user}
                for r in self.conn.response:
                    if r.get("type") == "searchResEntry":
                        op = {k: list(v) for k, v in r["raw_attributes"].items()
                              if k.lower() not in lower}
        return user, op

    # Schreiben -----------------------------------------------------------------
    def modify(self, dn: str, changes: dict[str, list]) -> None:
        if not changes:
            return
        mods = {name: [(MODIFY_REPLACE, values)] for name, values in changes.items()}
        self._check(self.conn.modify(dn, mods), "Speichern")

    def add(self, dn: str, object_classes: list[str], attributes: dict[str, list]) -> None:
        self._check(self.conn.add(dn, object_classes, attributes), "Anlegen")

    def subtree_dns(self, dn: str) -> list[str]:
        entries = self.search(dn, "(objectClass=*)", SUBTREE, NO_ATTRIBUTES)
        dns = [e["dn"] for e in entries]
        if not any(norm_dn(d) == norm_dn(dn) for d in dns):
            dns.append(dn)
        return dns

    def delete(self, dn: str, recursive: bool = False) -> int:
        targets = self.subtree_dns(dn) if recursive else [dn]
        targets.sort(key=lambda d: len(split_dn(d)), reverse=True)  # Blätter zuerst
        for target in targets:
            self._check(self.conn.delete(target), f"Löschen von {target}")
        return len(targets)

    def rename(self, dn: str, new_rdn: str, new_parent: str | None, delete_old: bool) -> str:
        kwargs = {"delete_old_dn": delete_old}
        if new_parent is not None:
            kwargs["new_superior"] = new_parent
        self._check(self.conn.modify_dn(dn, new_rdn, **kwargs), "Umbenennen/Verschieben")
        parent = new_parent if new_parent is not None else parent_of(dn)
        return f"{new_rdn},{parent}" if parent else new_rdn

    def password_modify(self, dn: str, new_password: str) -> bool:
        """RFC 3062 Password-Modify-Operation. False, wenn der Server sie nicht unterstützt."""
        try:
            result = self.conn.extend.standard.modify_password(user=dn, new_password=new_password)
        except LDAPException:
            return False
        return bool(result) and self._code() == 0

    def set_user_password_attr(self, dn: str, new_password: str, scheme: str = "SSHA512") -> str:
        """Setzt userPassword direkt – gehasht nach `scheme`. Gibt den gespeicherten Wert zurück."""
        value = hash_password(new_password, local_scheme(scheme))
        self.modify(dn, {"userPassword": [value]})
        return value

    # Gruppen -------------------------------------------------------------------
    # Mitgliedsattribute: (Attribut, Art) – "dn" = vollständiger DN, "uid" = Benutzername
    GROUP_TYPES = [
        ("groupofnames", "member", "dn"),
        ("groupofuniquenames", "uniqueMember", "dn"),
        ("group", "member", "dn"),                    # Active Directory
        ("posixgroup", "memberUid", "uid"),
    ]
    USER_CLASSES = ("inetorgperson", "person", "organizationalperson", "posixaccount",
                    "user", "account")

    @staticmethod
    def _classes(attrs: dict) -> set[str]:
        for name, values in attrs.items():
            if name.lower() == "objectclass":
                return {(v.decode() if isinstance(v, bytes) else str(v)).lower() for v in values}
        return set()

    def group_attr(self, attrs: dict) -> tuple[str, str] | None:
        """Ermittelt das Mitgliedsattribut einer Gruppe (z. B. ('member', 'dn'))."""
        classes = self._classes(attrs)
        for oc, attr, kind in self.GROUP_TYPES:
            if oc in classes:
                return attr, kind
        return None

    def is_user(self, attrs: dict) -> bool:
        return bool(self._classes(attrs) & set(self.USER_CLASSES)) and self.group_attr(attrs) is None

    def group_members(self, dn: str) -> tuple[str, str, list[str]]:
        attrs, _ = self.read(dn)
        info = self.group_attr(attrs)
        if info is None:
            raise LdapError("Dieser Eintrag ist keine bekannte Gruppe "
                            "(groupOfNames, groupOfUniqueNames, posixGroup, group).")
        attr, kind = info
        values = []
        for name, vals in attrs.items():
            if name.lower() == attr.lower():
                values = [v.decode("utf-8") for v in vals]
        return attr, kind, values

    def set_group_members(self, dn: str, attr: str, old: list[str], new: list[str]) -> None:
        key = (lambda v: norm_dn(v)) if attr.lower() != "memberuid" else (lambda v: v.lower())
        old_k = {key(v): v for v in old}
        new_k = {key(v): v for v in new}
        add = [v for k, v in new_k.items() if k not in old_k]
        remove = [v for k, v in old_k.items() if k not in new_k]
        if not add and not remove:
            return
        mods = []
        if add:
            mods.append((MODIFY_ADD, add))
        if remove:
            mods.append((MODIFY_DELETE, remove))
        self._check(self.conn.modify(dn, {attr: mods}), "Mitglieder speichern")

    def known_attrs(self, names) -> list[str]:
        """Nur Attribute, die das Server-Schema kennt (ldap3 prüft Namen sonst streng)."""
        schema = self.conn.server.schema
        if not schema:
            return list(names)
        known = {str(n).lower() for n in schema.attribute_types}
        return [n for n in names if n.lower() in known]

    def known_classes(self, names) -> list[str]:
        schema = self.conn.server.schema
        if not schema:
            return list(names)
        known = {str(n).lower() for n in schema.object_classes}
        return [n for n in names if n.lower() in known]

    def find_entries(self, text: str, kind: str = "user", limit: int = 200) -> list[dict]:
        """Sucht Benutzer oder Gruppen per Freitext. Liefert [{dn, label, uid}]."""
        base = self.roots()[0] if self.roots() else ""
        t = escape_filter_chars(text.strip())
        if kind == "group":
            classes = self.known_classes(["groupOfNames", "groupOfUniqueNames", "posixGroup",
                                          "group"])
            fields_ = self.known_attrs(["cn", "description"])
        else:
            classes = self.known_classes(["person", "posixAccount", "inetOrgPerson", "account"])
            fields_ = self.known_attrs(["cn", "uid", "mail", "sn", "givenName", "sAMAccountName"])
        if not classes:
            return []
        cls = "(|%s)" % "".join(f"(objectClass={c})" for c in classes)
        match = "(|%s)" % "".join(f"({f}=*{t}*)" for f in fields_) if t and fields_ else ""
        flt = f"(&{cls}{match})" if match else cls
        wanted = self.known_attrs(["cn", "uid", "mail", "sAMAccountName"])
        entries = self.search(base, flt, SUBTREE, wanted or NO_ATTRIBUTES, limit)
        out = []
        for e in entries:
            raw = {k.lower(): v for k, v in (e.get("raw_attributes") or {}).items()}
            first = lambda n: raw[n][0].decode("utf-8", "replace") if raw.get(n) else ""
            uid = first("uid") or first("samaccountname")
            label = first("cn") or rdn_of(e["dn"])
            extra = ", ".join(x for x in (uid, first("mail")) if x and x != label)
            out.append({"dn": e["dn"], "uid": uid,
                        "label": f"{label}  ({extra})" if extra else label})
        out.sort(key=lambda d: d["label"].lower())
        return out

    def groups_of(self, user_dn: str) -> list[dict]:
        """Gruppen, in denen der Benutzer Mitglied ist: [{dn, label, attr, value}]."""
        attrs, _ = self.read(user_dn)
        uid = ""
        for name, vals in attrs.items():
            if name.lower() == "uid" and vals:
                uid = vals[0].decode("utf-8")
        d = escape_filter_chars(user_dn)
        parts = [f"({a}={d})" for a in self.known_attrs(["member", "uniqueMember"])]
        if uid and self.known_attrs(["memberUid"]):
            parts.append(f"(memberUid={escape_filter_chars(uid)})")
        if not parts:
            return []
        base = self.roots()[0] if self.roots() else ""
        entries = self.search(base, f"(|{''.join(parts)})", SUBTREE, ["cn", "objectClass"])
        result = []
        for e in entries:
            raw = e.get("raw_attributes") or {}
            info = self.group_attr(raw)
            if info is None:
                continue
            attr, kind = info
            cn = next((v[0].decode() for k, v in raw.items() if k.lower() == "cn" and v), "")
            result.append({"dn": e["dn"], "label": cn or rdn_of(e["dn"]), "attr": attr,
                           "value": uid if kind == "uid" else user_dn})
        result.sort(key=lambda g: g["label"].lower())
        return result

    def member_value_for(self, user_dn: str, kind: str) -> str:
        if kind == "dn":
            return user_dn
        attrs, _ = self.read(user_dn)
        for name, vals in attrs.items():
            if name.lower() == "uid" and vals:
                return vals[0].decode("utf-8")
        raise LdapError(f"{rdn_of(user_dn)} hat kein uid-Attribut – kann nicht in eine "
                        "POSIX-Gruppe aufgenommen werden.")

    def add_to_group(self, group_dn: str, user_dn: str) -> None:
        attr, kind, members = self.group_members(group_dn)
        value = self.member_value_for(user_dn, kind)
        self.set_group_members(group_dn, attr, members, members + [value])

    def remove_from_group(self, group_dn: str, user_dn: str) -> None:
        attr, kind, members = self.group_members(group_dn)
        value = self.member_value_for(user_dn, kind)
        keep = [m for m in members if (norm_dn(m) != norm_dn(value) if kind == "dn"
                                       else m.lower() != value.lower())]
        if kind == "dn" and attr.lower() in ("member", "uniquemember") and not keep \
                and "groupofnames" in self._classes(self.read(group_dn)[0]):
            raise LdapError(f"{rdn_of(group_dn)}: groupOfNames braucht mindestens ein Mitglied.")
        self.set_group_members(group_dn, attr, members, keep)

    # Verschieben / Kopieren (Drag & Drop) ---------------------------------------
    @staticmethod
    def rebase_dn(dn: str, old_root: str, new_root: str) -> str:
        """Ersetzt den Anfang old_root eines DN (oder Untereintrags) durch new_root."""
        parts, root_parts = split_dn(dn), split_dn(old_root)
        keep = parts[:len(parts) - len(root_parts)]
        return ",".join(keep + [new_root]) if keep else new_root

    @staticmethod
    def is_same_or_below(dn: str, ancestor: str) -> bool:
        d, a = norm_dn(dn), norm_dn(ancestor)
        return d == a or d.endswith("," + a)

    def check_target(self, src: str, new_parent: str) -> str | None:
        """Gibt eine Fehlermeldung zurück, wenn src nicht nach new_parent kann."""
        if self.is_same_or_below(new_parent, src):
            return "Ein Eintrag kann nicht in sich selbst oder einen eigenen Untereintrag " \
                   "verschoben oder kopiert werden."
        return None

    def copy_subtree(self, src: str, new_parent: str, progress=None,
                     new_rdn: str | None = None) -> list[str]:
        """Kopiert src (inkl. aller Untereinträge) unter new_parent. Gibt neue DNs zurück."""
        problem = self.check_target(src, new_parent)
        if problem:
            raise LdapError(problem)
        entries = self.search(src, "(objectClass=*)", SUBTREE, [ALL_ATTRIBUTES])
        if not any(norm_dn(e["dn"]) == norm_dn(src) for e in entries):
            raise LdapError(f"Eintrag nicht gefunden:\n{src}")
        entries.sort(key=lambda e: len(split_dn(e["dn"])))      # Eltern zuerst
        root_rdn = (new_rdn or rdn_of(src)).strip()
        new_root = f"{root_rdn},{new_parent}" if new_parent else root_rdn
        created: list[str] = []
        for i, e in enumerate(entries, 1):
            target = self.rebase_dn(e["dn"], src, new_root)
            raw = e.get("raw_attributes") or {}
            classes = [v.decode("utf-8") if isinstance(v, bytes) else v
                       for n, vals in raw.items() if n.lower() == "objectclass" for v in vals]
            attrs = {n: list(vals) for n, vals in raw.items() if n.lower() != "objectclass"}
            if i == 1 and norm_dn(root_rdn) != norm_dn(rdn_of(src)):
                # Neuer Name: RDN-Wert im Eintrag selbst ersetzen
                old_a, old_v = (x.strip() for x in rdn_of(src).split("=", 1))
                new_a, new_v = (x.strip() for x in root_rdn.split("=", 1))
                for name in list(attrs):
                    if name.lower() == old_a.lower():
                        attrs[name] = [v for v in attrs[name]
                                       if v.decode("utf-8", "replace") != old_v]
                        if not attrs[name]:
                            del attrs[name]
                key = next((n for n in attrs if n.lower() == new_a.lower()), new_a)
                attrs.setdefault(key, []).append(new_v.encode("utf-8"))
            if progress:
                progress(i, len(entries), target)
            if not self.conn.add(target, classes, attrs):
                r = self.conn.result or {}
                done = f"\n\nBereits kopiert: {len(created)} von {len(entries)}." if created else ""
                msg = (r.get("message") or "").strip()
                raise LdapError(f"Kopieren nach {target} fehlgeschlagen: "
                                f"{r.get('description') or 'Fehler'}"
                                + (f"\n{msg}" if msg else "") + done)
            created.append(target)
        return created

    def update_references(self, mapping: dict[str, str]) -> int:
        """Ersetzt in Gruppen (member/uniqueMember) alte DNs durch neue. Gibt Anzahl Änderungen."""
        attrs = self.known_attrs(["member", "uniqueMember"])
        if not attrs or not mapping:
            return 0
        base = self.roots()[0] if self.roots() else ""
        changed = 0
        for old, new in mapping.items():
            d = escape_filter_chars(old)
            flt = "(|%s)" % "".join(f"({a}={d})" for a in attrs)
            for e in self.search(base, flt, SUBTREE, attrs):
                raw = e.get("raw_attributes") or {}
                for name, vals in raw.items():
                    hits = [v.decode("utf-8") for v in vals
                            if norm_dn(v.decode("utf-8", "replace")) == norm_dn(old)]
                    if hits:
                        ok = self.conn.modify(e["dn"], {name: [(MODIFY_ADD, [new]),
                                                               (MODIFY_DELETE, hits)]})
                        if ok:
                            changed += 1
        return changed

    def move_entry(self, src: str, new_parent: str, allow_copy_delete: bool = False,
                   update_refs: bool = True) -> dict:
        """
        Verschiebt src (mit Untereinträgen) unter new_parent.
        Kann der Server keine Teilbäume verschieben (Fehler 66), wird – wenn erlaubt –
        kopiert und das Original gelöscht. Ergebnis: {new_dn, method, refs}.
        """
        problem = self.check_target(src, new_parent)
        if problem:
            raise LdapError(problem)
        if norm_dn(parent_of(src)) == norm_dn(new_parent):
            raise LdapError("Der Eintrag liegt bereits dort.")
        new_dn = f"{rdn_of(src)},{new_parent}"
        old_dns = self.subtree_dns(src)
        mapping = {d: self.rebase_dn(d, src, new_dn) for d in old_dns}
        method = "modrdn"
        ok = self.conn.modify_dn(src, rdn_of(src), delete_old_dn=True, new_superior=new_parent)
        if not ok:
            if self._code() != 66:                             # 66 = notAllowedOnNonLeaf
                self._check(False, "Verschieben")
            if not allow_copy_delete:
                raise NonLeafMoveError("Der Server erlaubt nicht, Einträge mit Untereinträgen "
                                       "zu verschieben.")
            self.copy_subtree(src, new_parent)
            self.delete(src, recursive=True)
            method = "copy+delete"
        refs = self.update_references(mapping) if update_refs else 0
        return {"new_dn": new_dn, "method": method, "refs": refs, "count": len(old_dns)}

    # Eintrag als Vorlage ------------------------------------------------------
    # Persönliche/eindeutige Werte werden beim Kopieren geleert (Zeile bleibt zum Ausfüllen)
    COPY_CLEAR = {
        "uid", "cn", "sn", "givenname", "displayname", "initials", "mail",
        "mailalternateaddress", "employeenumber", "telephonenumber", "mobile", "homephone",
        "pager", "userpassword", "gecos", "samaccountname", "userprincipalname", "description",
        "labeleduri", "roomnumber", "carlicense",
    }
    # Vom Server verwaltete oder nicht kopierbare Attribute werden ganz weggelassen
    COPY_SKIP = {
        "memberof", "entryuuid", "entrydn", "createtimestamp", "modifytimestamp",
        "creatorsname", "modifiersname", "objectguid", "objectsid", "distinguishedname",
        "whencreated", "whenchanged", "usncreated", "usnchanged", "instancetype",
        "objectcategory", "samaccounttype", "pwdlastset", "badpwdcount", "badpasswordtime",
        "logoncount", "lastlogon", "lastlogoff", "lastlogontimestamp", "primarygroupid",
        "useraccountcontrol", "pwdchangedtime", "pwdaccountlockedtime", "pwdfailuretime",
        "pwdhistory", "jpegphoto", "thumbnailphoto",
    }

    def next_free_id(self, attr: str, start: int = 10000) -> int:
        """Nächste freie Nummer für uidNumber/gidNumber (höchster Wert + 1)."""
        if not self.known_attrs([attr]):
            return start
        base = self.roots()[0] if self.roots() else ""
        highest = start - 1
        for e in self.search(base, f"({attr}=*)", SUBTREE, [attr]):
            for k, vals in (e.get("raw_attributes") or {}).items():
                if k.lower() == attr.lower():
                    for v in vals:
                        try:
                            highest = max(highest, int(v))
                        except ValueError:
                            pass
        return highest + 1

    def copy_template(self, dn: str) -> dict:
        """Bereitet einen neuen Eintrag auf Basis von `dn` vor (für den Dialog „Neuer Eintrag“)."""
        attrs, _ = self.read(dn)
        classes = [v.decode("utf-8") for n, vals in attrs.items()
                   if n.lower() == "objectclass" for v in vals]
        lower_classes = {c.lower() for c in classes}
        rdn_attr = rdn_of(dn).split("=", 1)[0].strip()
        lines: list[str] = []
        cleared: list[str] = []
        skipped: set[str] = set()
        for name in sorted(attrs, key=str.lower):
            low = name.lower()
            vals = attrs[name]
            if low == "objectclass":
                continue
            if low in self.COPY_SKIP:
                skipped.add(name)
                continue
            if low in self.COPY_CLEAR or low == rdn_attr.lower():
                if low != rdn_attr.lower():
                    lines.append(f"{name}: ")
                cleared.append(name)
                continue
            if low == "uidnumber" and "posixaccount" in lower_classes:
                lines.append(f"{name}: {self.next_free_id('uidNumber')}")
                continue
            if low == "gidnumber" and "posixgroup" in lower_classes:
                lines.append(f"{name}: {self.next_free_id('gidNumber')}")
                continue
            if low == "homedirectory" and vals:
                home = vals[0].decode("utf-8", "replace")
                lines.append(f"{name}: {home.rsplit('/', 1)[0]}/" if "/" in home else f"{name}: ")
                continue
            for v in vals:
                text = decode_value(name, v)
                if text is None or "\n" in text:
                    skipped.add(name)
                    break
                lines.append(f"{name}: {text}")
        return {
            "source": dn, "parent": parent_of(dn), "rdn": f"{rdn_attr}=",
            "oc": ", ".join(classes), "attrs": "\n".join(lines),
            "cleared": cleared, "skipped": sorted(skipped, key=str.lower),
        }

    # LDIF-Import ---------------------------------------------------------------
    def import_records(self, records: list[LdifRecord], on_exists: str = "skip",
                       continue_on_error: bool = True, hash_scheme: str | None = None,
                       suffix_from: str = "", suffix_to: str = "", dry_run: bool = False,
                       progress=None) -> dict:
        """
        on_exists: 'skip' | 'replace' | 'error'  (bei add auf vorhandenen Eintrag)
        hash_scheme: Klartext-userPassword-Werte vor dem Import hashen (None = unverändert)
        Gibt {'ok', 'skipped', 'failed', 'log': [...]} zurück.
        """
        stats = {"ok": 0, "skipped": 0, "failed": 0, "log": []}

        def fix(value):
            return _replace_suffix(value, suffix_from, suffix_to)

        def prep(name, values):
            values = [fix(v) for v in values]
            if hash_scheme and name.lower() == "userpassword":
                values = [v if is_hashed(v) or isinstance(v, bytes)
                          else hash_password(v, hash_scheme) for v in values]
            return values

        for i, rec in enumerate(records, 1):
            dn = fix(rec.dn)
            if progress:
                progress(i, len(records), dn)
            try:
                if dry_run:
                    stats["ok"] += 1
                    stats["log"].append(f"TEST  {rec.changetype:7} {dn}")
                    continue
                if rec.changetype == "add":
                    attrs = {n: prep(n, v) for n, v in rec.attrs.items()}
                    classes = next((v for n, v in attrs.items() if n.lower() == "objectclass"), [])
                    rest = {n: v for n, v in attrs.items() if n.lower() != "objectclass"}
                    if self.conn.add(dn, classes, rest):
                        stats["ok"] += 1
                        stats["log"].append(f"OK    add     {dn}")
                        continue
                    if self._code() == 68 and on_exists == "skip":
                        stats["skipped"] += 1
                        stats["log"].append(f"SKIP  add     {dn} (existiert bereits)")
                        continue
                    if self._code() == 68 and on_exists == "replace":
                        self.modify(dn, rest)  # objectClass bleibt unverändert
                        stats["ok"] += 1
                        stats["log"].append(f"OK    update  {dn} (existierte, Attribute ersetzt)")
                        continue
                    self._check(False, "add")
                elif rec.changetype == "delete":
                    self._check(self.conn.delete(dn), "delete")
                    stats["ok"] += 1
                    stats["log"].append(f"OK    delete  {dn}")
                elif rec.changetype == "modify":
                    changes: dict[str, list] = {}
                    ops = {"add": MODIFY_ADD, "delete": MODIFY_DELETE, "replace": MODIFY_REPLACE}
                    for op, name, values in rec.mods:
                        changes.setdefault(name, []).append((ops[op], prep(name, values)))
                    self._check(self.conn.modify(dn, changes), "modify")
                    stats["ok"] += 1
                    stats["log"].append(f"OK    modify  {dn}")
                elif rec.changetype == "modrdn":
                    sup = fix(rec.newsuperior) if rec.newsuperior else None
                    self.rename(dn, rec.newrdn, sup, rec.deleteoldrdn)
                    stats["ok"] += 1
                    stats["log"].append(f"OK    modrdn  {dn} → {rec.newrdn}")
            except (LdapError, LDAPException) as exc:
                stats["failed"] += 1
                first = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
                stats["log"].append(f"FEHLER {rec.changetype:6} {dn}: {first}")
                if not continue_on_error:
                    stats["log"].append("Import abgebrochen.")
                    break
        return stats

    # Export --------------------------------------------------------------------
    def export_ldif(self, dn: str, path: str, scope=SUBTREE) -> int:
        entries = self.search(dn, "(objectClass=*)", scope, [ALL_ATTRIBUTES])
        entries.sort(key=lambda e: len(split_dn(e["dn"])))  # Eltern vor Kindern
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("version: 1\n\n")
            for e in entries:
                fh.write(ldif_line("dn", _as_bytes(e["dn"])) + "\n")
                raw = e.get("raw_attributes") or {}
                names = sorted(raw, key=lambda n: (n.lower() != "objectclass", n.lower()))
                for name in names:
                    for value in raw[name]:
                        fh.write(ldif_line(name, _as_bytes(value)) + "\n")
                fh.write("\n")
        return len(entries)


# --------------------------------------------------------------------------- #
# Demo-Server (offline, im Speicher)
# --------------------------------------------------------------------------- #
def demo_session() -> LdapSession:
    base = "dc=example,dc=org"
    admin = f"cn=admin,{base}"
    server = Server("demo.local", get_info=OFFLINE_SLAPD_2_4)
    conn = Connection(server, user=admin, password="demo", client_strategy=MOCK_SYNC,
                      raise_exceptions=False)
    s = conn.strategy
    s.add_entry(base, {"objectClass": ["top", "dcObject", "organization"],
                       "dc": "example", "o": "Example AG"})
    s.add_entry(admin, {"objectClass": ["top", "person"], "cn": "admin", "sn": "Admin",
                        "userPassword": "demo"})
    for ou in ("people", "groups", "services"):
        s.add_entry(f"ou={ou},{base}", {"objectClass": ["top", "organizationalUnit"], "ou": ou})
    people = [("anna", "Anna", "Muster", 10001), ("ben", "Ben", "Keller", 10002),
              ("clara", "Clara", "Weber", 10003), ("david", "David", "Huber", 10004)]
    for uid, given, sn, num in people:
        s.add_entry(f"uid={uid},ou=people,{base}", {
            "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
            "uid": uid, "cn": f"{given} {sn}", "givenName": given, "sn": sn,
            "mail": f"{uid}@example.org", "uidNumber": str(num), "gidNumber": "10000",
            "homeDirectory": f"/home/{uid}", "loginShell": "/bin/bash",
            "userPassword": hash_password("geheim", "SSHA512"),
        })
    s.add_entry(f"cn=admins,ou=groups,{base}", {
        "objectClass": ["top", "groupOfNames"], "cn": "admins",
        "member": [f"uid=anna,ou=people,{base}", f"uid=ben,ou=people,{base}"],
        "description": "Administratoren"})
    s.add_entry(f"cn=entwicklung,ou=groups,{base}", {
        "objectClass": ["top", "posixGroup"], "cn": "entwicklung", "gidNumber": "10000",
        "memberUid": ["clara", "david"]})
    s.add_entry(f"cn=mailrelay,ou=services,{base}", {
        "objectClass": ["top", "applicationProcess"], "cn": "mailrelay",
        "description": "Dienstkonto für das Mail-Relay"})
    if not conn.bind():
        raise LdapError("Demo-Server konnte nicht gestartet werden.")
    profile = Profile(name="Demo (offline)", host="demo.local", base_dn=base, bind_dn=admin)
    return LdapSession(profile, conn)
