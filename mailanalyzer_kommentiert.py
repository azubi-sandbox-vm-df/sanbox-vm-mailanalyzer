#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
mailanalyzer.py - Offline-Analyse verdaechtiger E-Mails im EML-Format

- Nur Python-Standardbibliothek (ab 3.9), KEINE Netzwerkzugriffe
- Dekodiert MIME korrekt (Base64, Quoted-Printable, RFC 2047, Charsets)
- Prueft Header, SPF/DKIM/DMARC, M365-Antispam-Header, URLs inkl. Redirect-/Safelinks-Ziele,
  Linktext-Mismatch, Tracking-Pixel, Base64-Blobs, data:-URIs, HTML-Smuggling und Anhaenge

Ablage:  <Basis>\<Ticket>_<Zeitstempel>\Analyse\<EML-Name>\{original.eml, report.json, Anhaenge\}
Aufruf:  python mailanalyzer.py -t INC-4711 mail.eml [weitere.eml | Ordner] [--base PFAD]
Exit:    0 = OK, 1 = Modulfehler, 2 = Eingabe-/Pfadfehler

Aufbau der Datei:
    1. Einstellungen         Pfade, Grenzwerte
    2. Konsole               Farben und Ausgabe-Helfer
    3. Muster und Listen     Regex, Dateiendungen, Magic-Bytes
    4. Hilfsfunktionen       Dekodierung, Dateityp, Namen, IPs, URLs
    5. HtmlScanner           HTML-Auswertung ohne Ausfuehrung
    6. MailAnalysis          Analyse einer EML (Header -> Inhalte -> Anhaenge -> Ausgabe -> Report)
    7. Rahmen                Eingaben, Defender-Pruefung, main()
"""

import argparse
import base64
import binascii
import hashlib
import html
import io
import ipaddress
import json
import logging
import mimetypes
import os
import re
import shutil
import sys
import time
import zipfile
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

# ------------------------------------------------------------------ Einstellungen

VERSION = "1.1"
DEFAULT_BASE = r"C:\Analyse\Proben"          # Basisordner, per --base ueberschreibbar
MAX_NAME_EML, MAX_NAME_ATT = 50, 80          # max. Laenge Fallordner / Anhangsname (Reserve fuer MAX_PATH 260)
MAX_TEXT_SCAN = 5 * 1024 * 1024              # max. Zeichen je gescanntem Text (Schutz vor Riesen-Mails)
MAX_BODY_IN_REPORT = 100_000                 # max. Zeichen je Body im report.json
B64_MIN_LEN = 40                             # Mindestlaenge eines Base64-Kandidaten im Text
B64_MAX_CANDIDATES = 300                     # max. gepruefte Base64-Kandidaten je Text (Laufzeitschutz)
MAX_DECODE_DEPTH = 2                         # max. Verschachtelung Base64 in Base64

log = logging.getLogger("mailanalyzer")

# ------------------------------------------------------------------ Konsole


class C:
    """ANSI-Farbcodes für die Konsolenausgabe.

    Klassenattribute: RED, GREEN, YELLOW, BLUE, CYAN, GREY, BOLD, RESET
    Werden von disable() geleert, wenn keine Farbausgabe gewünscht ist.
    """
    RED, GREEN, YELLOW, BLUE = "\033[91m", "\033[92m", "\033[93m", "\033[94m"
    CYAN, GREY, BOLD, RESET = "\033[96m", "\033[90m", "\033[1m", "\033[0m"

    @classmethod
    def disable(cls):
        """Schaltet alle Farben ab, indem die Farbcodes durch Leerstrings ersetzt werden.

        Aufgerufen von: main() bei --no-color oder umgeleiteter Ausgabe (keine Konsole).
        """
        for name in ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "GREY", "BOLD", "RESET"):
            setattr(cls, name, "")


LEVEL_ORDER = {"HOCH": 0, "MITTEL": 1, "INFO": 2}


def color_of(level):
    """Liefert den Farbcode zu einer Befundstufe.

    Parameter:
        level: "HOCH" (rot), "MITTEL" (gelb), alles andere (cyan)
    Rückgabe: ANSI-Farbcode aus Klasse C
    """
    return {"HOCH": C.RED, "MITTEL": C.YELLOW}.get(level, C.CYAN)


def section(title):
    """Gibt eine Abschnittsüberschrift mit Trennlinien auf der Konsole aus.

    Parameter:
        title: Überschrift des Abschnitts
    """
    print(f"\n{C.BLUE}{'=' * 78}\n {title}\n{'=' * 78}{C.RESET}")


def kv(key, value, color=""):
    """Gibt eine eingerückte Zeile "Schlüssel  Wert" aus.

    Parameter:
        key:   Bezeichnung (linksbündig, 20 Zeichen breit)
        value: anzuzeigender Wert
        color: optionaler Farbcode für den Wert
    """
    print(f"  {C.GREEN}{key:<20}{C.RESET}{color}{value}{C.RESET}")


def trunc(s, n=160):
    """Kürzt einen Text für die Konsolenausgabe und hängt "..." an.

    Parameter:
        s: beliebiger Wert (wird in str umgewandelt)
        n: maximale Länge inkl. "..."
    Rückgabe: gekürzter String
    """
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


# ------------------------------------------------------------------ Muster und Listen

# IPv4-Adressen (Validierung erfolgt anschliessend ueber ipaddress)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# IPv6-Adressen in [ ] oder ( ), wie sie in Received-Headern stehen
IPV6_RE = re.compile(r"[\[(](?:IPv6:)?([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)[\])]")
# E-Mail-Adressen; Top-Level-Domain muss aus Buchstaben bestehen (filtert cid:-Referenzen)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
# URLs im Klartext, inkl. entschaerfter hxxp:// und www.-Angaben ohne Schema
URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?|ftp)://[^\s<>\"'`]+|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>\"'`]*")
# url(...) in CSS (style-Attribute und <style>-Bloecke)
CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", re.I)
# data:-URIs; Gruppen: 1 MIME-Typ, 2 Parameter, 3 ";base64", 4 Nutzdaten
DATA_URI_RE = re.compile(r"data:([a-z0-9.+/-]*)((?:;[a-z0-9.+-]+=[^;,\s]*)*)(;base64)?,([A-Za-z0-9+/=%_\-\s]{8,})", re.I)
# zusammenhaengende Base64-Zeichenketten (Standard und URL-safe) ab B64_MIN_LEN Zeichen
B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{%d,}={0,2})(?![A-Za-z0-9+/=_-])" % B64_MIN_LEN)
# Unicode-Richtungszeichen (RTLO-Trick: "Rechnung\u202efdp.exe" wird als "Rechnungexe.pdf" angezeigt)
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")
# Doppel-Endungen wie "rechnung.pdf.exe"
DOUBLE_EXT_RE = re.compile(r"(?i)\.[a-z0-9]{2,5}\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|ps1|lnk|"
                           r"iso|img|vhdx?|msi|jar|cpl|dll|one|html?|svg)$")
# Linktext, der wie eine URL/Domain aussieht (fuer die Linktext/Ziel-Pruefung)
TEXT_IS_DOMAIN_RE = re.compile(r"(?i)^(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?:[/:?#]\S*)?$")
# typische Pfadbestandteile von Tracking-Pixeln
PIXEL_KW_RE = re.compile(r"(?i)(track|pixel|beacon|/open|open\.|/o\.gif|/t\.gif|spacer|impression|/imp[/?]|"
                         r"/wf/open|mailtrack|/e/o/|/count)")
# CSS, das Elemente unsichtbar macht (Leerzeichen werden vorher entfernt)
HIDDEN_CSS_RE = re.compile(r"display:none|visibility:hidden|opacity:0(?:\.0+)?(?:;|$|!)|max-height:0|max-width:0")
# JavaScript-Muster fuer HTML-Smuggling und Verschleierung
SMUGGLING_RE = re.compile(r"(?i)(atob\s*\(|new\s+Blob\s*\(|createObjectURL|msSaveOrOpenBlob|\.download\s*=|"
                          r"fromCharCode|unescape\s*\(|eval\s*\()")
# Ergebnisse aus Authentication-Results, z. B. "dmarc=fail"
AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)")
# URL-Pfade, die auf ausfuehrbare Dateien oder Archive zeigen
DOWNLOAD_EXT_RE = re.compile(r"(?i)\.(exe|scr|msi|zip|rar|7z|iso|img|vhdx?|js|jse|vbs|hta|lnk|one|ps1|bat|cmd|jar|apk)$")

# Endungen mit hohem Risiko (ausfuehrbar, Container, Verknuepfungen) -> Befund HOCH
EXEC_EXT = set(".exe .scr .com .pif .bat .cmd .js .jse .vbs .vbe .wsf .wsh .hta .ps1 .psm1 .lnk .iso .img .vhd "
               ".vhdx .msi .msix .appx .jar .cpl .dll .one .xll .chm .reg .url .library-ms .settingcontent-ms".split())
# pruefwuerdige Endungen (HTML, Makro-Office, Archive) -> Befund MITTEL
WATCH_EXT = set(".html .htm .shtml .xhtml .svg .docm .xlsm .pptm .dotm .xlam .zip .rar .7z .ace .cab .gz .tgz "
                ".r00 .arj".split())
# Endungen, deren Inhalt als HTML ausgewertet wird
HTML_EXT = {".htm", ".html", ".shtml", ".xhtml", ".svg"}
# bekannte URL-Shortener (verschleiern das Ziel)
SHORTENERS = set("bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at rb.gy tiny.cc "
                 "s.id t.ly bl.ink lnkd.in".split())
# Query-Parameter, in denen Weiterleitungsziele stehen (Safelinks, Tracking-Links)
REDIRECT_PARAMS = set("url u q redirect redirect_url redirect_uri redir target dest destination link goto r rurl "
                      "returnurl return_url next continue".split())
# unter Windows reservierte Dateinamen
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}
# M365-Filterkategorien (CAT:), die als HOCH gewertet werden
M365_BAD_CAT = {"PHSH", "HPHSH", "HPHISH", "MALW", "SPOOF"}

MAGIC = [  # (Offset, Signatur, Typ)
    (0, b"MZ", "PE/Windows-Executable"), (0, b"\x7fELF", "ELF-Executable"),
    (0, b"PK\x03\x04", "ZIP-Container"), (0, b"PK\x05\x06", "ZIP-Container (leer)"),
    (0, b"%PDF", "PDF"), (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/CFB (doc/xls/ppt/msg)"),
    (0, b"Rar!\x1a\x07", "RAR"), (0, b"7z\xbc\xaf\x27\x1c", "7-Zip"), (0, b"\x1f\x8b", "GZIP"),
    (0, b"MSCF", "CAB"), (0, b"{\\rtf", "RTF"), (0, b"L\x00\x00\x00\x01\x14\x02\x00", "LNK-Verknuepfung"),
    (0, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3", "OneNote"),
    (0, b"\x89PNG\r\n\x1a\n", "PNG"), (0, b"\xff\xd8\xff", "JPEG"), (0, b"GIF87a", "GIF"), (0, b"GIF89a", "GIF"),
    (0x8001, b"CD001", "ISO-Image"), (0x8801, b"CD001", "ISO-Image"), (0x9001, b"CD001", "ISO-Image"),
]
# per Magic-Bytes erkannte Typen, die immer als HOCH gelten
HIGH_RISK_TYPES = {"PE/Windows-Executable", "ELF-Executable", "LNK-Verknuepfung", "OneNote", "ISO-Image"}

EXPECTED = {  # Dateiendung -> erwartete Teilstrings von detect_type()
    ".pdf": ("PDF",), ".rtf": ("RTF",), ".iso": ("ISO",), ".one": ("OneNote",), ".lnk": ("LNK",),
    ".zip": ("ZIP", "OOXML", "JAR"), ".jar": ("JAR", "ZIP"), ".rar": ("RAR",), ".7z": ("7-Zip",), ".gz": ("GZIP",),
    ".png": ("PNG",), ".jpg": ("JPEG",), ".jpeg": ("JPEG",), ".gif": ("GIF",),
    ".htm": ("HTML",), ".html": ("HTML",), ".svg": ("SVG", "XML"),
    **{e: ("OLE",) for e in (".doc", ".xls", ".ppt", ".msg")},
    **{e: ("OOXML",) for e in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm")},
    **{e: ("PE",) for e in (".exe", ".dll", ".scr")},
}

# ------------------------------------------------------------------ Hilfsfunktionen


def hashes(data):
    """Berechnet MD5, SHA1 und SHA256 (z. B. für VirusTotal- oder Defender-Abgleich).

    Parameter:
        data: Dateiinhalt als bytes
    Rückgabe: dict {"md5", "sha1", "sha256"}
    """
    return {"md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def as_text(data, min_ratio=0.95):
    """Prüft, ob Bytes überwiegend druckbarer UTF-8-Text sind.

    Parameter:
        data:      zu prüfende bytes
        min_ratio: Mindestanteil druckbarer Zeichen (Standard 95 %)
    Rückgabe: dekodierter Text oder None (Binärdaten/Datenmüll)
    """
    t = data.decode("utf-8", errors="replace")
    if not t:
        return None
    good = sum(1 for ch in t if ch != "\ufffd" and (ch.isprintable() or ch in "\r\n\t"))
    return t if good / len(t) >= min_ratio else None


def detect_type(data):
    """Ermittelt den tatsächlichen Dateityp anhand der Magic-Bytes (unabhängig von der Endung).

    Parameter:
        data: Dateiinhalt als bytes
    Nutzt: MAGIC (Signaturtabelle), zip_subtype(), as_text()
    Rückgabe: Typbezeichnung, z. B. "PDF", "PE/Windows-Executable", "HTML", "Text", "unbekannt"
    """
    for off, sig, name in MAGIC:
        if data[off:off + len(sig)] == sig:
            return zip_subtype(data) if name == "ZIP-Container" else name
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "SVG"
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta")) or b"<html" in head[:512]:
        return "HTML"
    if head.startswith(b"<?xml"):
        return "XML"
    return "Text" if as_text(data[:4096]) is not None else "unbekannt"


def zip_subtype(data):
    """Unterscheidet ZIP-basierte Formate anhand der enthaltenen Pfade.

    Parameter:
        data: ZIP-Inhalt als bytes
    Rückgabe: "OOXML Word/Excel/PowerPoint", "JAR (Java-Archiv)" oder "ZIP-Container"
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
    except Exception:
        return "ZIP-Container"
    for prefix, name in (("word/", "OOXML Word"), ("xl/", "OOXML Excel"), ("ppt/", "OOXML PowerPoint")):
        if any(n.startswith(prefix) for n in names):
            return name
    return "JAR (Java-Archiv)" if "META-INF/MANIFEST.MF" in names else "ZIP-Container"


def sanitize_name(name, max_len, fallback):
    r"""Macht einen Dateinamen aus der Mail sicher für das Speichern unter Windows.

    Entfernt Pfadanteile (Schutz vor Path-Traversal wie ..\..\), Steuer- und
    Bidi-Zeichen (RTLO-Trick), ungültige Zeichen und reservierte Namen (CON, NUL, ...).

    Parameter:
        name:     ursprünglicher Dateiname (darf None sein)
        max_len:  maximale Länge inkl. Endung (MAX_PATH-Reserve)
        fallback: Ersatzname, wenn nichts Verwertbares übrig bleibt
    Rückgabe: bereinigter Dateiname
    """
    name = BIDI_RE.sub("_", (name or "").strip()).replace("\\", "/").split("/")[-1]
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", name).strip(" .") or fallback
    stem, ext = os.path.splitext(name)
    if stem.upper() in WIN_RESERVED:
        stem = "_" + stem
    ext = ext[:15]
    return stem[: max(1, max_len - len(ext))] + ext


def unique_path(directory, name):
    """Liefert einen noch nicht belegten Pfad (hängt bei Bedarf _1, _2, ... an).

    Parameter:
        directory: Zielordner (Path)
        name:      gewünschter Dateiname
    Rückgabe: freier Pfad (Path)
    """
    stem, ext = os.path.splitext(name)
    p, i = directory / name, 1
    while p.exists():
        p, i = directory / f"{stem}_{i}{ext}", i + 1
    return p


def ip_type(obj):
    """Klassifiziert eine IP-Adresse.

    Parameter:
        obj: ipaddress.IPv4Address oder IPv6Address
    Rückgabe: "Loopback", "Link-Local", "Multicast", "Reserviert", "Privat" oder "Oeffentlich"
    """
    for attr, label in (("is_loopback", "Loopback"), ("is_link_local", "Link-Local"), ("is_multicast", "Multicast"),
                        ("is_unspecified", "Reserviert"), ("is_reserved", "Reserviert"), ("is_private", "Privat")):
        if getattr(obj, attr):
            return label
    return "Oeffentlich"


def extract_ips(text):
    """Sucht IPv4- und (in Klammern stehende) IPv6-Adressen und validiert sie.

    Parameter:
        text: zu durchsuchender Text (z. B. ein Received-Header)
    Rückgabe: Liste eindeutiger, gültiger IPs in Fundreihenfolge
    """
    out = []
    for cand in IPV4_RE.findall(text) + IPV6_RE.findall(text):
        try:
            ip = str(ipaddress.ip_address(cand))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def base_domain(d):
    """Ermittelt näherungsweise die registrierte Domain (ohne Public-Suffix-Liste).

    Parameter:
        d: Hostname, z. B. "mail.example.co.uk"
    Rückgabe: z. B. "example.co.uk"
    """
    p = d.split(".")
    return ".".join(p[-3:] if len(p) >= 3 and len(p[-2]) <= 3 and len(p[-1]) == 2 else p[-2:])


def domains_related(a, b):
    """Prüft, ob zwei Domains zusammengehören (gleich, Subdomain oder gleiche Basis-Domain).

    Parameter:
        a, b: Domains; ist eine davon leer, gilt das Paar als zusammengehörig
    Rückgabe: True/False
    """
    if not a or not b:
        return True
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a) or base_domain(a) == base_domain(b)


def addr_domain(addr):
    """Extrahiert die Domain aus einer E-Mail-Adresse.

    Parameter:
        addr: Adresse, ggf. in spitzen Klammern
    Rückgabe: Domain in Kleinbuchstaben oder ""
    """
    addr = (addr or "").strip().strip("<>").lower()
    return addr.rsplit("@", 1)[1] if "@" in addr else ""


def clean_url(raw):
    """Bereinigt eine gefundene URL: HTML-Entities auflösen, Leerraum und Satzzeichen am Ende entfernen.

    Parameter:
        raw: URL wie im Text/Attribut gefunden
    Rückgabe: bereinigte URL
    """
    return re.sub(r"\s+", "", html.unescape(raw or "").strip()).rstrip(".,;:!?)]}'\">")


def normalize_url(u):
    """Vereinheitlicht URLs für Vergleich und Parsing.

    hxxp:// -> http://, www.x -> http://www.x, //host -> https://host

    Parameter:
        u: bereinigte URL
    Rückgabe: normalisierte URL
    """
    low = u.lower()
    if low.startswith("hxxp"):
        return "http" + u[4:]
    if low.startswith("www."):
        return "http://" + u
    return "https:" + u if u.startswith("//") else u


def host_of(url):
    """Liefert den Hostnamen einer URL in Kleinbuchstaben.

    Parameter:
        url: normalisierte URL
    Rückgabe: Hostname oder "" bei ungültiger URL
    """
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def redirect_targets(url):
    """Liest Weiterleitungsziele aus Query-Parametern (Safelinks ?url=, Google ?q=, ...).

    Parameter:
        url: normalisierte URL
    Nutzt: REDIRECT_PARAMS (Liste typischer Parameternamen)
    Rückgabe: Liste der dekodierten Ziel-URLs
    """
    try:
        q = parse_qs(urlparse(url).query)
    except ValueError:
        return []
    return [normalize_url(unquote(v).strip()) for k, vals in q.items() if k.lower() in REDIRECT_PARAMS
            for v in vals if re.match(r"(?i)^(https?:)?//", unquote(v).strip())]


def defang_url(u):
    """Entschärft eine URL für die Ausgabe (nicht anklickbar).

    Beispiel: https://evil.com/x -> hxxps[://]evil[.]com/x

    Parameter:
        u: URL
    Rückgabe: entschärfte URL
    """
    m = re.match(r"(?i)^([a-z][a-z0-9+.-]*)://([^/?#]*)(.*)$", u)
    if not m:
        return u.replace(".", "[.]")
    scheme, netloc, rest = m.groups()
    scheme = re.sub(r"(?i)^ftp", "fxp", re.sub(r"(?i)^http", "hxxp", scheme))
    return f"{scheme}[://]{netloc.replace('.', '[.]')}{rest}"


def defang(s):
    """Entschärft Domains und E-Mail-Adressen (. -> [.], @ -> [@]).

    Parameter:
        s: Domain oder Adresse
    Rückgabe: entschärfter String
    """
    return s.replace("@", "[@]").replace(".", "[.]")


def try_b64(s):
    """Versucht einen String als Base64 (Standard oder URL-safe) zu dekodieren.

    Fehlendes Padding (=) wird ergänzt.

    Parameter:
        s: Base64-Kandidat
    Rückgabe: dekodierte bytes oder None
    """
    s = re.sub(r"\s", "", s).replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def get_text(part):
    """Liefert den dekodierten Text eines MIME-Teils (Base64/QP und Charset werden aufgelöst).

    Fällt bei unbekanntem oder defektem Charset auf UTF-8 mit Ersatzzeichen zurück.

    Parameter:
        part: email.message.EmailMessage (Blatt-Teil)
    Rückgabe: Text als str
    """
    try:
        c = part.get_content()
        return c.decode("utf-8", "replace") if isinstance(c, bytes) else str(c)
    except Exception:
        raw = part.get_payload(decode=True) or b""
        try:
            return raw.decode(part.get_content_charset() or "utf-8", "replace")
        except LookupError:
            return raw.decode("utf-8", "replace")


def iter_parts(msg, depth=0, path="1"):
    """Durchläuft rekursiv alle MIME-Teile einer Mail.

    Parameter:
        msg:   Mail oder MIME-Teil
        depth: Verschachtelungstiefe (erhöht sich nur bei angehängten Mails)
        path:  MIME-Pfad, z. B. "1.2.1"
    Liefert (yield): (Art, Teil, depth, path)
        Art = "container" (multipart), "rfc822" (angehängte Mail) oder "leaf" (Inhalt)
    """
    if not msg.is_multipart():
        yield ("leaf", msg, depth, path)
        return
    rfc822 = msg.get_content_type() == "message/rfc822"
    yield ("rfc822" if rfc822 else "container", msg, depth, path)
    for i, sub in enumerate(msg.get_payload(), 1):
        yield from iter_parts(sub, depth + rfc822, f"{path}.{i}")


def pixel_score(img):
    """Bewertet ein externes <img> heuristisch als Tracking-Pixel.

    Punkte: Größe <= 1px (+3), CSS-Größe <= 1px (+3), per CSS versteckt (+3),
    Tracking-Schlüsselwort im Pfad (+1), ID-/Token-Parameter (+1), Token im Pfad (+1),
    GIF/PNG mit Query-Parametern (+1). Ab 2 "möglich", ab 3 "wahrscheinlich".

    Parameter:
        img: Attribute des <img>-Tags als dict (src, width, height, style)
    Rückgabe: (score, Liste der Gründe)
    """
    src, score, reasons = img.get("src", ""), 0, []

    def hit(points, reason):
        """Addiert Punkte und merkt sich den Grund (schreibt score/reasons der äußeren Funktion)."""
        nonlocal score
        score += points
        reasons.append(reason)

    dims = [img.get(k) for k in ("width", "height")]
    if any(m and float(m.group(1)) <= 1 for m in (re.match(r"\s*(\d+(?:\.\d+)?)", str(d)) for d in dims if d)):
        hit(3, f"Groesse {dims[0] or '?'}x{dims[1] or '?'}")
    st = re.sub(r"\s+", "", img.get("style", "").lower())
    css = re.search(r"(?<![a-z-])(width|height):(\d+(?:\.\d+)?)(?:px)?(?=;|$|!)", st)
    if css and float(css.group(2)) <= 1:
        hit(3, f"CSS {css.group(1)}:{css.group(2)}")
    if HIDDEN_CSS_RE.search(st):
        hit(3, "per CSS versteckt")
    if PIXEL_KW_RE.search(src):
        hit(1, "Tracking-Schluesselwort im Pfad")
    try:
        p = urlparse(normalize_url(src))
        if any(re.fullmatch(r"[A-Za-z0-9_\-=%.]{16,}", v) for vals in parse_qs(p.query).values() for v in vals):
            hit(1, "ID-/Token-Parameter")
        if any(re.fullmatch(r"[A-Za-z0-9_\-=]{24,}", seg) for seg in p.path.split("/")):
            hit(1, "Token im Pfad")
        if re.search(r"(?i)\.(gif|png)$", p.path) and p.query:
            hit(1, "Bild mit Query-Parametern")
    except ValueError:
        pass
    return score, reasons


class HtmlScanner(HTMLParser):
    """HTML-Parser auf Basis von html.parser (Standardbibliothek), führt nichts aus.

    Sammelt nach feed()/close():
        urls:     Liste (URL, Tag, Attribut) aus href, src, action, srcset, CSS url(), meta refresh
        images:   Attribute aller <img>-Tags (für die Tracking-Pixel-Prüfung)
        anchors:  Links als dict {"href", "text"} (für die Linktext-Prüfung)
        forms:    action-Ziele aller <form>-Tags
        scripts:  Anzahl der <script>-Blöcke
        visible:  sichtbarer Text (ohne script/style), abrufbar über visible_text()
    """
    URL_ATTRS = {"href", "src", "action", "background", "data", "poster", "formaction", "cite", "longdesc",
                 "lowsrc", "dynsrc"}

    def __init__(self):
        """Legt die Ergebnislisten an.

        Interne Zustände:
            _skip:   > 0, solange der Parser in <script>/<style> steht (Text ist dann nicht sichtbar)
            _open_a: Stapel offener <a>-Tags, um den Linktext zu sammeln
        """
        super().__init__(convert_charrefs=True)
        self.urls, self.images, self.anchors, self.forms, self.visible = [], [], [], [], []
        self.scripts, self._skip, self._open_a = 0, 0, []

    def handle_starttag(self, tag, attrs):
        """Wird für jedes öffnende Tag aufgerufen und sammelt URLs, Bilder, Links und Formulare.

        Parameter:
            tag:   Tagname in Kleinbuchstaben
            attrs: Liste (Attribut, Wert)
        Schreibt: urls, images, _open_a, forms, scripts, _skip
        """
        a = {k.lower(): (v or "") for k, v in attrs}
        for k, v in a.items():
            if k in self.URL_ATTRS and v.strip():
                self.urls.append((v.strip(), tag, k))
            elif k == "srcset":
                self.urls += [(i.strip().split(" ")[0], tag, k) for i in v.split(",") if i.strip()]
            elif k == "style":
                self.urls += [(u, tag, "style") for u in CSS_URL_RE.findall(v)]
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.urls.append((m.group(1).strip(), "meta", "refresh"))
        if tag == "img":
            self.images.append(a)
        elif tag == "a":
            self._open_a.append({"href": a.get("href", ""), "text": ""})
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag in ("script", "style"):
            self.scripts += tag == "script"
            self._skip += 1

    def handle_endtag(self, tag):
        """Schließt offene Links ab, verlässt script/style und setzt Zeilenumbrüche für den sichtbaren Text.

        Parameter:
            tag: Tagname
        Schreibt: anchors, _skip, visible
        """
        if tag == "a" and self._open_a:
            self.anchors.append(self._open_a.pop())
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag in ("p", "div", "br", "tr", "li", "h1", "h2", "h3", "table"):
            self.visible.append("\n")

    def handle_data(self, data):
        """Verarbeitet Textinhalt zwischen Tags.

        Linktext geht an den offenen <a>-Tag, CSS-url() aus <style> geht an urls, sichtbarer Text an visible.

        Parameter:
            data: Textinhalt
        """
        if self._open_a:
            self._open_a[-1]["text"] += data
        if self._skip:
            self.urls += [(u, "style", "css") for u in CSS_URL_RE.findall(data)]
        else:
            self.visible.append(data)

    def close(self):
        """Beendet das Parsen und übernimmt nicht geschlossene <a>-Tags in anchors."""
        super().close()
        self.anchors += reversed(self._open_a)
        self._open_a = []

    def visible_text(self):
        """Liefert den sichtbaren Text mit bereinigtem Leerraum (für die Body-Vorschau).

        Rückgabe: Text als str
        """
        t = re.sub(r"[ \t\xa0]+", " ", "".join(self.visible))
        return re.sub(r"\n\s*\n+", "\n\n", t).strip()


# ------------------------------------------------------------------ Analyse je EML


class MailAnalysis:
    """Analyse einer einzelnen EML-Datei. Ergebnisse landen in Attributen und in report.json.

    Wichtige Attribute:
        eml_path, case_dir, att_dir   Quelle, Fallordner, Ordner "Anhaenge"
        msg                           geparste Mail (email.message.EmailMessage)
        findings                      Befunde [{"stufe", "text"}], Stufen HOCH/MITTEL/INFO
        errors                        Modulfehler (Analyse läuft trotzdem weiter)
        urls                          {normalisierte URL: Eintrag mit host, befunde, weiterleitung_zu, quellen}
        ips, emails                   IOCs ({IP: {typ, quellen}}, set)
        attachments, saved            Anhangs-Einträge bzw. (Eintrag, Pfad) gespeicherter Dateien
        pixels, external_images       Tracking-Pixel und alle externen Bilder
        mismatches, forms, smuggling  Linktext-Abweichungen, Formulare, HTML-Smuggling-Indikatoren
        b64_hits                      dekodierte Base64-Blobs und data:-URIs
    """
    def __init__(self, eml_path, case_dir, ticket):
        r"""Initialisiert alle Ergebnis-Container für eine Mail.

        Parameter:
            eml_path: Pfad zur EML-Datei
            case_dir: Fallordner ...\Analyse\<EML-Name> (muss existieren, inkl. Unterordner Anhaenge)
            ticket:   bereinigte Ticketnummer (für den Report)
        """
        self.eml_path, self.case_dir, self.ticket = eml_path, case_dir, ticket
        self.att_dir = case_dir / "Anhaenge"
        self.msg, self.source = None, {}
        self.findings, self.errors = [], []
        self.header, self.auth, self.m365 = {}, {}, {}
        self.received, self.mime, self.bodies = [], [], []
        self.urls, self.ips, self.emails = {}, {}, set()
        self.pixels, self.external_images, self.mismatches = [], [], []
        self.forms, self.smuggling, self.b64_hits, self.x_headers = [], [], [], []
        self.attachments, self.saved = [], []
        self._b64_seen, self._embedded = set(), 0

    # ---------- Infrastruktur

    def finding(self, level, text):
        """Fügt einen Befund hinzu (ohne Duplikate) und schreibt ihn ins Log.

        Parameter:
            level: "HOCH", "MITTEL" oder "INFO"
            text:  Befundtext
        Schreibt: self.findings
        """
        if {"stufe": level, "text": text} not in self.findings:
            self.findings.append({"stufe": level, "text": text})
            log.info("[%s] %s: %s", self.eml_path.name, level, text)

    def flag(self, entry, level, short, text=None):
        """Vermerkt einen Befund am Objekt (Anhang/URL) UND in der Befundliste der Mail.

        Parameter:
            entry: dict des Anhangs bzw. der URL (bekommt den Kurztext in entry["befunde"])
            level: Befundstufe
            short: Kurztext für das Objekt
            text:  ausführlicher Text für die Befundliste (Standard: short)
        """
        entry.setdefault("befunde", []).append(short)
        self.finding(level, text or short)

    def module(self, name, func):
        """Führt ein Analysemodul abgesichert aus. Ein Fehler stoppt nicht die übrigen Module.

        Parameter:
            name: Modulname für Ausgabe und Log
            func: aufzurufende Methode ohne Parameter
        Schreibt bei Fehler: self.errors, Log (mit Traceback)
        """
        try:
            func()
        except Exception as e:
            self.errors.append(f"{name}: {type(e).__name__}: {e}")
            log.exception("[%s] Modul '%s' fehlgeschlagen", self.eml_path.name, name)
            print(f"  {C.RED}[!] Modul '{name}' fehlgeschlagen: {type(e).__name__}: {e}{C.RESET}")

    def hdr(self, name):
        """Liest alle Werte eines Headers dekodiert (RFC 2047) und einzeilig.

        Fällt auf Rohwerte zurück, wenn die Dekodierung fehlschlägt.

        Parameter:
            name: Headername, z. B. "Received"
        Liest: self.msg
        Rückgabe: Liste der Werte (leer, wenn nicht vorhanden)
        """
        try:
            vals = self.msg.get_all(name) or []
        except Exception as e:
            log.warning("Header %s nicht dekodierbar (%s), Rohwert wird verwendet", name, e)
            vals = [v for k, v in self.msg.raw_items() if k.lower() == name.lower()]
        return [" ".join(str(v).split()) for v in vals]

    def add_ip(self, ip, source):
        """Validiert eine IP und nimmt sie mit Fundstelle in die IOC-Liste auf.

        Parameter:
            ip:     IP-Adresse als String (ungültige werden verworfen)
            source: Fundstelle, z. B. "Received Hop 2"
        Schreibt: self.ips
        """
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return
        self.ips.setdefault(str(obj), {"typ": ip_type(obj), "quellen": set()})["quellen"].add(source)

    def add_emails(self, text):
        """Sucht E-Mail-Adressen im Text und nimmt sie in die IOC-Liste auf.

        Parameter:
            text: zu durchsuchender Text
        Schreibt: self.emails
        """
        self.emails.update(e.lower() for e in EMAIL_RE.findall(text or ""))

    # ---------- Ablauf

    def run(self, copy_original=True):
        """Hauptablauf für eine Mail: einlesen, kopieren, parsen, alle Module ausführen, Befunde ausgeben.

        Parameter:
            copy_original: True = EML als original.eml in den Fallordner kopieren (aus --no-copy)
        Schreibt: self.source, self.msg und über die Module alle Ergebnis-Attribute
        Löst aus: ValueError bei Outlook-MSG-Dateien, OSError bei Lesefehlern (Abfang in main())
        """
        raw = self.eml_path.read_bytes()
        if raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            raise ValueError("Datei ist im Outlook-MSG-Format (OLE), nicht EML. Bitte als .eml exportieren.")
        self.source = {"pfad": str(self.eml_path.resolve()), "groesse": len(raw), **hashes(raw)}
        if copy_original:
            try:
                shutil.copy2(self.eml_path, self.case_dir / "original.eml")
            except OSError as e:
                self.errors.append(f"Kopie original.eml: {e}")
                log.warning("original.eml konnte nicht kopiert werden: %s", e)
        self.msg = BytesParser(policy=policy.default).parsebytes(raw)

        section(f"ANALYSE: {self.eml_path.name}")
        kv("Datei", f"{self.source['pfad']} ({len(raw)} Bytes)")
        kv("SHA256", self.source["sha256"])
        kv("Ablage", str(self.case_dir))
        for name, func in (("Header", self.analyze_headers), ("Authentifizierung", self.analyze_auth),
                           ("M365-Antispam", self.analyze_m365), ("Received-Kette", self.analyze_received),
                           ("MIME/Inhalte/Anhaenge", self.analyze_parts), ("URLs", self.print_urls),
                           ("Tracking-Pixel", self.print_pixels), ("IOCs", self.print_iocs),
                           ("X-Header", self.analyze_x_headers)):
            self.module(name, func)
        self.print_findings()

    # ---------- Header

    def analyze_headers(self):
        """Gibt die wichtigsten Header aus und prüft Absender-Auffälligkeiten.

        Prüft: mehrere From-Header, fremde Adresse im Anzeigenamen (Spoofing),
        Reply-To- und Return-Path-Domain abweichend von der From-Domain, fehlende Message-ID.
        Liest: self.msg (über hdr)
        Schreibt: self.header, self.emails, self.ips, self.findings
        """
        section("Header")
        for name in ("From", "Sender", "Reply-To", "Return-Path", "To", "Cc", "Bcc", "Subject", "Date",
                     "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP", "List-Unsubscribe"):
            vals = self.hdr(name)
            if not vals:
                continue
            self.header[name] = vals if len(vals) > 1 else vals[0]
            for v in vals:
                kv(name, trunc(v, 200), C.YELLOW if name in ("From", "Reply-To", "Return-Path") else "")
                if name not in ("Subject", "Date", "Message-ID", "X-Mailer", "User-Agent"):
                    self.add_emails(v)
        for v in self.hdr("X-Originating-IP"):
            for ip in extract_ips(v):
                self.add_ip(ip, "X-Originating-IP")

        froms = self.hdr("From")
        if not froms:
            return self.finding("MITTEL", "Kein From-Header vorhanden")
        if len(froms) > 1:
            self.finding("HOCH", f"Mehrere From-Header ({len(froms)})")
        disp, from_addr = parseaddr(froms[0])
        from_dom = addr_domain(from_addr)
        foreign = [e for e in EMAIL_RE.findall(disp) if e.lower() != from_addr.lower()]
        if foreign:
            self.finding("HOCH", f"Anzeigename enthaelt fremde Adresse '{foreign[0]}' (tatsaechlich: {from_addr})")
        for hname, level, note in (("Reply-To", "MITTEL", ""),
                                   ("Return-Path", "INFO", " (bei Newsletter-Dienstleistern normal)")):
            for v in self.hdr(hname):
                dom = addr_domain(parseaddr(v)[1])
                if dom and not domains_related(from_dom, dom):
                    self.finding(level, f"{hname}-Domain ({dom}) weicht von From-Domain ({from_dom}) ab{note}")
        if not self.hdr("Message-ID"):
            self.finding("INFO", "Keine Message-ID vorhanden")

    def analyze_auth(self):
        """Wertet SPF, DKIM, DMARC, ARC und compauth aus Authentication-Results und Received-SPF aus.

        Liest: Header "Authentication-Results", "Received-SPF"
        Schreibt: self.auth ({Mechanismus: [Ergebnisse]}), self.findings
        """
        section("Authentifizierung (SPF / DKIM / DMARC)")
        res = {}
        for v in self.hdr("Authentication-Results"):
            for mech, val in AUTH_RE.findall(v):
                lst = res.setdefault(mech.lower(), [])
                if val.lower() not in lst:
                    lst.append(val.lower())
        for v in self.hdr("Received-SPF"):
            if v:
                res.setdefault("received-spf", []).append(v.split()[0].lower())
        self.auth = res
        if not res:
            print("  Keine Authentication-Results-/Received-SPF-Header vorhanden.")
            return self.finding("INFO", "Keine Authentifizierungs-Ergebnisse im Header")
        for mech, vals in res.items():
            kv(mech.upper(), ", ".join(vals), C.GREEN if all(v == "pass" for v in vals) else C.RED)
        for mechs, bad, level, text in ((("dmarc",), {"fail"}, "HOCH", "DMARC fail"),
                                        (("compauth",), {"fail"}, "HOCH", "compauth fail (M365 Composite Authentication)"),
                                        (("spf", "received-spf"), {"fail", "softfail"}, "MITTEL", "SPF fail/softfail"),
                                        (("dkim",), {"fail"}, "MITTEL", "DKIM fail")):
            if any(v in bad for m in mechs for v in res.get(m, [])):
                self.finding(level, text)
        print(f"  {C.GREY}Hinweis: Nur Ergebnisse des eigenen Empfangssystems sind belastbar, "
              f"Header weiter unten kann der Absender faelschen.{C.RESET}")

    def analyze_m365(self):
        """Liest die Microsoft-365-Antispam-Header als Rohwerte aus (keine eigene Interpretation).

        Liest: "X-Forefront-Antispam-Report" (CIP, CTRY, SCL, SFV, CAT, ...), "X-Microsoft-Antispam" (BCL),
               "X-MS-Exchange-Organization-SCL"
        Schreibt: self.m365, self.ips (CIP), self.findings (CAT, SCL >= 5)
        """
        fa, ma = self.hdr("X-Forefront-Antispam-Report"), self.hdr("X-Microsoft-Antispam")
        scl = self.hdr("X-MS-Exchange-Organization-SCL")
        if not (fa or ma or scl):
            return
        section("Microsoft 365 Antispam-Header (Rohwerte)")
        fields = {k.strip().upper(): val.strip() for v in fa for item in v.split(";") if ":" in item
                  for k, val in [item.split(":", 1)]}
        self.m365 = {k: fields[k] for k in ("CIP", "CTRY", "LANG", "SCL", "SFV", "CAT", "PTR", "IPV", "H", "SRV", "SFTY")
                     if k in fields}
        bcl = next((m.group(1) for v in ma for m in [re.search(r"BCL:(\d+)", v)] if m), None)
        if bcl:
            self.m365["BCL"] = bcl
        if scl:
            self.m365["Org-SCL"] = scl[0]
        print("  " + " | ".join(f"{C.GREEN}{k}{C.RESET}:{v}" for k, v in self.m365.items()))
        if "CIP" in fields:
            self.add_ip(fields["CIP"], "M365 CIP (verbindende IP)")
        cat = fields.get("CAT", "").upper()
        if cat:
            self.finding("HOCH" if cat in M365_BAD_CAT else "INFO", f"M365-Filter-Kategorie CAT:{cat}")
        for val in (fields.get("SCL"), scl[0] if scl else None):
            if val and val.lstrip("-").isdigit() and int(val) >= 5:
                self.finding("MITTEL", f"M365 Spam Confidence Level (SCL) {val}")
                break

    def analyze_received(self):
        """Wertet die Received-Kette chronologisch aus (älteste Station zuerst).

        Pro Hop: from-Host, by-Host, IPs und Zeitstempel. Die erste öffentliche IP im from-Teil
        wird als vermutliche Ursprungs-IP ausgegeben (Heuristik).
        Liest: Header "Received"
        Schreibt: self.received, self.ips, self.header["_ursprungs_ip"]
        """
        section("Received-Kette (chronologisch, aelteste zuerst)")
        chain = list(reversed(self.hdr("Received")))
        origin = None
        for i, r in enumerate(chain, 1):
            frm, by = re.search(r"(?i)\bfrom\s+(\S+)", r), re.search(r"(?i)\bby\s+(\S+)", r)
            from_ips = extract_ips(re.split(r"(?i)\bby\b", r, maxsplit=1)[0])
            all_ips = extract_ips(r)
            for ip in all_ips:
                self.add_ip(ip, f"Received Hop {i}")
            origin = origin or next((ip for ip in from_ips if ip_type(ipaddress.ip_address(ip)) == "Oeffentlich"), None)
            hop = {"hop": i, "from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
                   "ips_from": from_ips, "ips_alle": all_ips, "datum": r.rsplit(";", 1)[1].strip() if ";" in r else ""}
            self.received.append(hop)
            print(f"  {C.CYAN}[{i:02d}]{C.RESET} from {trunc(hop['from'], 45)} {C.YELLOW}{', '.join(from_ips)}{C.RESET} "
                  f"-> by {trunc(hop['by'], 45)}\n       {C.GREY}{hop['datum']}{C.RESET}")
        kv("Hops", len(chain))
        if origin:
            kv("Ursprungs-IP*", f"{origin}  {C.GREY}(* erster oeffentlicher from-Hop, Heuristik)", C.YELLOW)
        self.header["_ursprungs_ip"] = origin

    # ---------- MIME, Bodies, Anhaenge

    def analyze_parts(self):
        """Zerlegt die Mail in MIME-Teile und verteilt sie auf Body- und Anhangsanalyse.

        Ablauf: MIME-Struktur ausgeben -> Text-Bodies dekodieren und scannen -> Anhänge speichern und prüfen.
        Body = text/plain oder text/html ohne Dateinamen und nicht als attachment markiert.
        Liest: self.msg
        Schreibt: self.mime, self.bodies, self.findings; ruft scan_text() und save_attachment() auf
        """
        section("MIME-Struktur")
        if self.msg.defects:
            d = ", ".join(sorted({type(x).__name__ for x in self.msg.defects}))
            print(f"  {C.YELLOW}Defekte (Top-Level): {d}{C.RESET}")
            self.finding("INFO", f"MIME-Defekte im Top-Level: {d}")
        bodies, attachments = [], []
        for kind, part, depth, path in iter_parts(self.msg):
            ctype, disp = part.get_content_type(), part.get_content_disposition()
            try:
                fname = part.get_filename()
            except Exception:
                fname = None
            cte = str(part.get("Content-Transfer-Encoding", "") or "").lower()
            defects = sorted({type(x).__name__ for x in part.defects}) if part is not self.msg else []
            self.mime.append({"pfad": path, "typ": ctype, "cte": cte, "disposition": disp, "dateiname": fname,
                              "charset": part.get_content_charset(), "defekte": defects})
            indent = "  " * path.count(".")
            extra = " ".join(x for x in (cte, disp or "", f'"{fname}"' if fname else "") if x)
            print(f"  {indent}{path:<10} {ctype:<28} {C.GREY}{extra}{C.RESET}")
            if defects:
                print(f"  {indent}{C.YELLOW}  Defekte: {', '.join(defects)}{C.RESET}")
                self.finding("INFO", f"MIME-Defekte in Teil {path}: {', '.join(defects)}")
            if kind == "rfc822":
                attachments.append(("rfc822", part, path, fname))
            elif kind == "leaf":
                is_body = ctype in ("text/plain", "text/html") and disp != "attachment" and not fname
                (bodies if is_body else attachments).append((kind, part, path, fname if not is_body else depth))

        section("Mail-Inhalt")
        preview_done = False
        for _, part, path, depth in bodies:
            ctype, text = part.get_content_type(), get_text(part)
            is_html = ctype == "text/html"
            label = f"Body {path} ({ctype}{', angehaengte Mail' if depth else ''})"
            self.bodies.append({"mime_pfad": path, "typ": ctype, "zeichen": len(text), "text": text[:MAX_BODY_IN_REPORT]})
            if not preview_done:
                preview_done = self.print_preview(text, is_html, label)
            self.scan_text(text, label, is_html=is_html)
        if not bodies:
            print("  Kein Text-Body gefunden.")

        section("Anhaenge und eingebettete Objekte")
        if not attachments:
            print("  Keine MIME-Anhaenge gefunden.")
        for kind, part, path, fname in attachments:
            if kind == "rfc822":
                self.save_attached_mail(part, path, fname)
                continue
            data = part.get_payload(decode=True)
            if data is None:
                p = part.get_payload()
                data = p.encode("utf-8", "replace") if isinstance(p, str) else b""
            ctype = part.get_content_type()
            origin = "Inline" if part.get_content_disposition() == "inline" or part.get("Content-ID") else "Anhang"
            self.save_attachment(data, fname or f"unbenannt_{path}{mimetypes.guess_extension(ctype) or '.bin'}",
                                 ctype, f"{origin} (MIME {path})", path, charset=part.get_content_charset())

    def print_preview(self, text, is_html, label):
        """Gibt die ersten 1500 Zeichen des Mailtexts aus (bei HTML nur der sichtbare Text).

        Parameter:
            text:    Body-Inhalt
            is_html: True, wenn text HTML ist
            label:   Bezeichnung des Body für die Ausgabe
        Rückgabe: True, wenn eine Vorschau ausgegeben wurde
        """
        if is_html:
            p = HtmlScanner()
            try:
                p.feed(text)
                p.close()
                text = p.visible_text()
            except Exception:
                pass
        text = re.sub(r"\n\s*\n+", "\n\n", text.replace("\r", "")).strip()
        if text:
            print(f"  {C.GREY}Vorschau aus {label}, max. 1500 Zeichen:{C.RESET}\n\n{C.YELLOW}{text[:1500]}{C.RESET}\n")
        return bool(text)

    def save_attached_mail(self, part, path, fname):
        """Speichert eine angehängte Mail (message/rfc822) als .eml im Anhangsordner.

        Ihre Inhalte werden nicht erneut gescannt, das erledigt bereits iter_parts().

        Parameter:
            part:  MIME-Teil vom Typ message/rfc822
            path:  MIME-Pfad
            fname: Dateiname aus dem Header (darf None sein)
        """
        payload = part.get_payload()
        sub = payload[0] if isinstance(payload, list) and payload else None
        self.finding("INFO", f"Angehaengte E-Mail (MIME {path})")
        if sub is None:
            return
        print(f"  {C.CYAN}[Mail {path}]{C.RESET} From: {trunc(sub.get('From', ''), 80)} | "
              f"Subject: {trunc(sub.get('Subject', ''), 80)}")
        try:
            data = sub.as_bytes()
        except Exception as e:
            return log.warning("Angehaengte Mail %s nicht serialisierbar: %s", path, e)
        # Inhalte der angehaengten Mail werden bereits ueber iter_parts analysiert -> scan=False
        self.save_attachment(data, fname or f"angehaengte_mail_{path}.eml", "message/rfc822",
                             f"angehaengte Mail (MIME {path})", path, scan=False)

    def save_attachment(self, data, orig_name, declared, origin, part_path, scan=True, charset=None):
        """Prüft einen Anhang (oder ein eingebettetes Objekt) und speichert ihn im Anhangsordner.

        Prüfungen: RTLO-Zeichen, Doppel-Endung, riskante Endung, Magic-Bytes vs. Endung,
        ZIP/OOXML-, OLE- und PDF-Indikatoren. Text- und HTML-Anhänge werden zusätzlich mit scan_text() gescannt.

        Parameter:
            data:      Inhalt als bytes
            orig_name: Dateiname aus der Mail
            declared:  deklarierter MIME-Typ (Content-Type)
            origin:    Herkunft für den Report, z. B. "Anhang (MIME 1.2)"
            part_path: MIME-Pfad oder "-" für eingebettete Objekte
            scan:      False = Inhalt nicht nach URLs/Base64 durchsuchen
            charset:   Zeichensatz für Text-Anhänge
        Schreibt: self.attachments, self.saved, Datei in self.att_dir
        Rückgabe: Anhangs-Eintrag (dict)
        """
        name = sanitize_name(orig_name, MAX_NAME_ATT, "anhang.bin")
        ext, detected = os.path.splitext(name)[1].lower(), detect_type(data)
        entry = {"herkunft": origin, "mime_pfad": part_path, "originalname": orig_name, "dateiname": name,
                 "deklarierter_typ": declared, "erkannter_typ": detected, "groesse": len(data),
                 **hashes(data), "befunde": []}

        if BIDI_RE.search(orig_name or ""):
            self.flag(entry, "HOCH", "Unicode-Richtungszeichen (RTLO-Trick) im Dateinamen",
                      f"RTLO/Bidi-Zeichen im Anhangsnamen: {orig_name!r}")
        if DOUBLE_EXT_RE.search(name):
            self.flag(entry, "HOCH", "Doppel-Endung", f"Doppel-Endung: {name}")
        if ext in EXEC_EXT:
            self.flag(entry, "HOCH", f"ausfuehrbarer/riskanter Typ ({ext})", f"Riskanter Anhangstyp {ext}: {name}")
        elif ext in WATCH_EXT:
            self.flag(entry, "MITTEL", f"pruefwuerdiger Typ ({ext})", f"Pruefwuerdiger Anhangstyp {ext}: {name}")
        if detected in HIGH_RISK_TYPES:
            self.flag(entry, "HOCH", f"Inhalt: {detected}", f"Anhang '{name}' ist inhaltlich {detected}")
        exp = EXPECTED.get(ext)
        if exp and detected != "unbekannt" and not any(t in detected for t in exp):
            self.flag(entry, "HOCH" if detected in HIGH_RISK_TYPES else "MITTEL",
                      f"Endung {ext} passt nicht zum Inhalt ({detected})", f"Endung/Inhalt-Mismatch: {name} ist {detected}")
        if detected.startswith(("ZIP", "OOXML", "JAR")):
            self.zip_checks(data, name, entry)
        elif detected.startswith("OLE"):
            self.ole_checks(data, name, entry)
        elif detected == "PDF":
            self.pdf_checks(data, name, entry)

        path = unique_path(self.att_dir, name)
        try:
            path.write_bytes(data)
            entry["gespeichert"] = str(path)
            self.saved.append((entry, path))
        except OSError as e:
            entry["speicherfehler"] = f"{type(e).__name__}: {e}"
            self.flag(entry, "HOCH", "Schreiben blockiert (vermutlich AV/Defender)",
                      f"Schreiben von '{name}' blockiert, vermutlich durch AV: {e}")
        self.attachments.append(entry)
        self.print_attachment(entry)

        is_html = detected in ("HTML", "SVG") or ext in HTML_EXT or declared in ("text/html", "image/svg+xml")
        if scan and (is_html or detected in ("XML", "Text") or declared.startswith("text/")
                     or ext in (".url", ".ics", ".txt")):
            try:
                text = data.decode(charset or "utf-8", "replace")
            except LookupError:
                text = data.decode("utf-8", "replace")
            self.scan_text(text, f"Anhang {name}", is_html=is_html, attachment_ctx=True)
        return entry

    def print_attachment(self, e):
        """Gibt einen Anhangs-Eintrag auf der Konsole aus (Typ, SHA256, Befunde, ZIP-Inhalt).

        Parameter:
            e: Anhangs-Eintrag aus save_attachment()
        """
        col = C.RED if any(f["stufe"] == "HOCH" and e["dateiname"] in f["text"] for f in self.findings) else C.CYAN
        print(f"\n  {col}[+] {e['dateiname']}{C.RESET}  {C.GREY}({e['herkunft']}, {e['groesse']} Bytes){C.RESET}")
        kv("  Typ", f"deklariert: {e['deklarierter_typ'] or '-'} | erkannt: {e['erkannter_typ']}")
        kv("  SHA256", e["sha256"])
        for fl in e["befunde"]:
            print(f"    {C.YELLOW}! {fl}{C.RESET}")
        for z in e.get("zip_inhalt", [])[:20]:
            print(f"    {C.GREY}- {trunc(z['name'], 90)} ({z['groesse']} B)"
                  f"{' [verschluesselt]' if z['verschluesselt'] else ''}{C.RESET}")
        if len(e.get("zip_inhalt", [])) > 20:
            print(f"    {C.GREY}... {len(e['zip_inhalt']) - 20} weitere{C.RESET}")

    def zip_checks(self, data, name, entry):
        """Prüft ZIP-basierte Dateien (ZIP, docx/xlsx/pptx, JAR), ohne etwas zu entpacken.

        Prüft: Verschlüsselung, riskante Dateien im Archiv, VBA-Makros, ActiveX, eingebettete OLE-Objekte,
        externe Referenzen in .rels (Remote-Template-Injection).

        Parameter:
            data:  Inhalt als bytes
            name:  bereinigter Dateiname (für Befundtexte)
            entry: Anhangs-Eintrag (bekommt "zip_inhalt" und Befunde)
        """
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                names = [zi.filename for zi in infos]
                entry["zip_inhalt"] = [{"name": zi.filename, "groesse": zi.file_size,
                                        "verschluesselt": bool(zi.flag_bits & 0x1)} for zi in infos[:500]]
                if any(zi.flag_bits & 0x1 for zi in infos):
                    self.flag(entry, "HOCH", "passwortgeschuetztes Archiv",
                              f"Verschluesseltes Archiv (umgeht AV-Scan): {name}")
                risky = [n for n in names if os.path.splitext(n)[1].lower() in EXEC_EXT or DOUBLE_EXT_RE.search(n)]
                if risky:
                    self.flag(entry, "HOCH", f"riskante Dateien im Archiv: {', '.join(risky[:5])}",
                              f"Archiv '{name}' enthaelt riskante Dateien: {', '.join(risky[:5])}")
                for test, level, text in ((lambda n: n.lower().endswith("vbaproject.bin"), "HOCH", "VBA-Makroprojekt"),
                                          (lambda n: "activex" in n.lower(), "MITTEL", "ActiveX-Objekte"),
                                          (lambda n: "embeddings/oleobject" in n.lower(), "MITTEL", "eingebettete OLE-Objekte")):
                    if any(test(n) for n in names):
                        self.flag(entry, level, text, f"{text} in '{name}'")
                for zi in infos:
                    if zi.filename.endswith(".rels") and zi.file_size < 1_000_000 and not zi.flag_bits & 0x1:
                        rel = z.read(zi)
                        if b'TargetMode="External"' in rel and any(k in rel for k in (b"attachedTemplate", b"oleObject", b"frame")):
                            self.flag(entry, "HOCH", f"externe Referenz (Remote-Template/OLE) in {zi.filename}",
                                      f"Externe Template-/OLE-Referenz in '{name}'")
                            break
        except zipfile.BadZipFile as e:
            entry["befunde"].append(f"ZIP defekt: {e}")
        except Exception as e:
            log.warning("ZIP-Pruefung %s: %s", name, e)

    def ole_checks(self, data, name, entry):
        """Sucht in alten Office-Formaten (doc/xls/ppt) nach Makro- und Paket-Streams.

        Parameter:
            data:  Inhalt als bytes
            name:  bereinigter Dateiname
            entry: Anhangs-Eintrag (bekommt Befunde)
        """
        for key, level, text in (("_VBA_PROJECT", "HOCH", "VBA-Projekt (Makros wahrscheinlich)"),
                                 ("Macros", "MITTEL", "Macros-Speicher"),
                                 ("Ole10Native", "HOCH", "eingebettetes Paket (Ole10Native)")):
            if key.encode("utf-16-le") in data:   # Stream-Namen in OLE sind UTF-16LE
                self.flag(entry, level, text, f"{text} in '{name}'")

    def pdf_checks(self, data, name, entry):
        """Zählt PDF-Schlüsselwörter für aktive Inhalte (/JavaScript, /OpenAction, /Launch, ...).

        Heuristik: verschleierte Schlüsselwörter (z. B. /J#61vaScript) werden nicht erkannt.

        Parameter:
            data:  Inhalt als bytes
            name:  bereinigter Dateiname
            entry: Anhangs-Eintrag (bekommt "pdf_indikatoren" und Befunde)
        """
        counts = {k: n for k in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
                                 "/SubmitForm", "/XFA", "/URI", "/ObjStm")
                  if (n := len(re.findall(re.escape(k.encode()) + rb"(?![A-Za-z])", data)))}
        if not counts:
            return
        entry["pdf_indikatoren"] = counts
        entry["befunde"].append("PDF-Indikatoren: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
        if counts.keys() & {"/JavaScript", "/JS", "/Launch", "/EmbeddedFile"}:
            self.finding("HOCH", f"PDF '{name}' enthaelt aktive Inhalte ({', '.join(counts)})")
        elif counts.keys() & {"/OpenAction", "/AA", "/SubmitForm", "/XFA"}:
            self.finding("MITTEL", f"PDF '{name}' enthaelt Auto-Aktionen/Formulare ({', '.join(counts)})")

    # ---------- Text-/HTML-Scan (rekursiv fuer dekodierte Inhalte)

    def scan_text(self, text, label, is_html, depth=0, attachment_ctx=False):
        """Zentraler Inhalts-Scan für Bodies, Text-/HTML-Anhänge und dekodierte Blobs.

        Ablauf: HTML parsen (scan_html) -> Smuggling-Indikatoren -> data:-URIs dekodieren ->
        URLs, E-Mail-Adressen und IPs per Regex -> Base64-Blobs suchen (rekursiv bis MAX_DECODE_DEPTH).

        Parameter:
            text:           zu scannender Text
            label:          Fundstelle für Ausgabe und Report
            is_html:        True = zusätzlich HTML-Struktur auswerten
            depth:          aktuelle Dekodiertiefe (Schutz vor Endlosschleifen)
            attachment_ctx: True bei Anhängen/dekodierten Inhalten (Formulare/Scripts werden strenger bewertet)
        Schreibt: self.smuggling, self.urls, self.emails, self.ips, self.findings
        """
        if not text:
            return
        if len(text) > MAX_TEXT_SCAN:
            log.info("%s auf %d Zeichen gekuerzt", label, MAX_TEXT_SCAN)
            text = text[:MAX_TEXT_SCAN]
        if is_html:
            self.scan_html(text, label, attachment_ctx)
            text = html.unescape(text)

        hits = sorted({re.sub(r"\s+", " ", m.group(1)) for m in SMUGGLING_RE.finditer(text)})
        if hits:
            self.smuggling.append({"quelle": label, "indikatoren": hits})
            low = " ".join(hits).lower()
            strong = "atob" in low and ("blob" in low or "createobjecturl" in low)
            self.finding("HOCH" if strong or attachment_ctx else "MITTEL",
                         f"{label}: JavaScript-/HTML-Smuggling-Indikatoren ({', '.join(hits)})")

        text = DATA_URI_RE.sub(lambda m: self.handle_data_uri(m, label, depth), text)
        for u in URL_RE.findall(text):
            self.add_url(u, f"{label} (Text)")
        self.add_emails(text)
        for ip in IPV4_RE.findall(text):
            self.add_ip(ip, label)
        if depth < MAX_DECODE_DEPTH:
            self.scan_b64(text, label, depth)

    def scan_html(self, text, label, attachment_ctx):
        """Wertet die HTML-Struktur aus: URLs, Bilder (Tracking-Pixel), Links (Linktext) und Formulare.

        Parameter:
            text:           HTML-Inhalt
            label:          Fundstelle
            attachment_ctx: True = Formular mit externem Ziel gilt als HOCH (Credential Harvesting)
        Schreibt: self.forms, self.findings; ruft add_url(), check_image(), check_anchor() auf
        """
        p = HtmlScanner()
        try:
            p.feed(text)
            p.close()
        except Exception as e:
            log.warning("HTML-Parser %s: %s", label, e)
        for u, tag, attr in p.urls:
            self.add_url(u, f"{label} <{tag} {attr}>")
        for img in p.images:
            self.check_image(img, label)
        for a in p.anchors:
            self.check_anchor(a, label)
        for act in p.forms:
            self.forms.append({"quelle": label, "action": act})
            external = bool(re.match(r"(?i)^(https?:)?//", act.strip()))
            if attachment_ctx and external:
                self.finding("HOCH", f"{label}: Formular sendet an externe URL ({defang_url(clean_url(act))})")
            elif attachment_ctx or external:
                self.finding("MITTEL", f"{label}: enthaelt HTML-Formular")
        if p.scripts and attachment_ctx:
            self.finding("MITTEL", f"{label}: enthaelt {p.scripts} <script>-Block(e)")

    def handle_data_uri(self, m, label, depth):
        """Callback für re.sub(): dekodiert eine data:-URI und entfernt sie aus dem Text.

        Parameter:
            m:     Regex-Treffer von DATA_URI_RE (Gruppe 1 = MIME-Typ, 3 = ";base64", 4 = Nutzdaten)
            label: Fundstelle
            depth: aktuelle Dekodiertiefe
        Rückgabe: " " (Ersatztext, damit scan_b64() die Daten nicht doppelt findet)
        """
        data = try_b64(m.group(4)) if m.group(3) else unquote(m.group(4)).encode("utf-8", "replace")
        if data:
            self.handle_decoded(data, f"{label} data-URI", depth, "data-URI", mime=(m.group(1) or "").lower())
        return " "   # data-URI aus dem Text entfernen, damit scan_b64 sie nicht erneut findet

    def scan_b64(self, text, label, depth):
        """Sucht längere Base64-Zeichenketten im Text und dekodiert sie probeweise.

        Verworfen werden Hex-Werte, sehr kurze Ergebnisse und Daten ohne erkennbaren Typ (zufällige Token).

        Parameter:
            text:  zu durchsuchender Text
            label: Fundstelle
            depth: aktuelle Dekodiertiefe
        Nutzt: B64_RE, B64_MAX_CANDIDATES
        """
        for count, m in enumerate(B64_RE.finditer(text)):
            if count >= B64_MAX_CANDIDATES:
                log.info("%s: Limit fuer Base64-Kandidaten erreicht", label)
                break
            s = m.group(1)
            if re.fullmatch(r"[0-9a-fA-F]+", s.rstrip("=")):
                continue                                   # Hex-Werte (Hashes, IDs)
            data = try_b64(s)
            if data and len(data) >= 24 and detect_type(data) != "unbekannt":   # zufaellige Token verwerfen
                self.handle_decoded(data, f"{label} Base64-Blob", depth, "Base64-Blob")

    def handle_decoded(self, data, label, depth, kind, mime=""):
        """Bewertet dekodierte Base64-/data:-URI-Daten.

        Text/HTML wird erneut mit scan_text() durchsucht, Binärobjekte (ZIP, PE, ...) werden als
        eingebettet_NN_<Typ>.bin gespeichert, damit YARA-X und Defender sie prüfen können.

        Parameter:
            data:  dekodierte bytes
            label: Fundstelle
            depth: aktuelle Dekodiertiefe
            kind:  "data-URI" oder "Base64-Blob"
            mime:  MIME-Typ aus der data:-URI (sonst leer)
        Schreibt: self.b64_hits, self._b64_seen (Duplikatschutz), ggf. Datei über save_attachment()
        """
        key = hashlib.sha256(data).hexdigest()
        if key in self._b64_seen:
            return
        self._b64_seen.add(key)
        t = detect_type(data)
        info = {"quelle": label, "art": kind, "mime": mime, "groesse": len(data), "sha256": key, "erkannt": t}
        self.b64_hits.append(info)
        text = as_text(data) if t in ("HTML", "SVG", "XML", "Text") else None
        if text is not None:
            info["vorschau"] = trunc(text.replace("\n", " "), 200)
            print(f"  {C.CYAN}[B64]{C.RESET} {label}: {t}, {len(data)} B -> {C.GREY}{trunc(info['vorschau'], 90)}{C.RESET}")
            self.scan_text(text, f"{label} (dekodiert)", is_html=t in ("HTML", "SVG"), depth=depth + 1,
                           attachment_ctx=True)
        save = t not in ("Text", "unbekannt") or (kind == "data-URI" and t == "unbekannt" and len(data) >= 64)
        if t in ("PNG", "JPEG", "GIF") and len(data) < 2048:
            save = False                                   # Signatur-/Logo-Grafiken
        if save:
            self._embedded += 1
            if t in HIGH_RISK_TYPES or t.startswith(("ZIP", "OOXML", "JAR", "RAR", "7-Zip", "OLE")):
                self.finding("HOCH", f"Eingebettetes Objekt ({t}) in {label}")
            name = f"eingebettet_{self._embedded:02d}_{re.sub(r'[^A-Za-z0-9]+', '_', t).strip('_')}.bin"
            entry = self.save_attachment(data, name, mime, f"eingebettet: {label}", "-", scan=False)
            info["gespeichert_als"] = entry.get("gespeichert", entry.get("speicherfehler"))

    # ---------- URLs / Bilder / Links

    def add_url(self, raw, source, _depth=0):
        """Nimmt eine URL auf, bewertet sie und verfolgt Weiterleitungsziele.

        Prüft: IP als Host, Punycode, Nicht-ASCII-Host, @ im Host-Teil, URL-Shortener,
        Nicht-Standard-Port, Datei-Download. mailto: liefert E-Mail-Adressen, cid:/data:/# werden ignoriert.

        Parameter:
            raw:    URL wie gefunden
            source: Fundstelle
            _depth: interne Rekursionstiefe für Weiterleitungen (max. 3)
        Schreibt: self.urls, self.ips, self.emails, self.findings
        """
        u = clean_url(raw)
        low = u.lower()
        if not u or low.startswith(("cid:", "data:", "#", "about:", "tel:", "sms:")):
            return
        if low.startswith("mailto:"):
            return self.add_emails(unquote(u[7:].split("?")[0]))
        if low.startswith(("javascript:", "vbscript:")):
            return self.finding("MITTEL", f"{source}: Script-URL ({trunc(u, 60)})")
        norm = normalize_url(u)
        if not re.match(r"(?i)^(https?|ftp)://", norm):
            return
        if norm in self.urls:
            return self.urls[norm]["quellen"].add(source)
        try:
            p = urlparse(norm)
            port = p.port
        except ValueError:
            p, port = None, None
        host = host_of(norm)
        entry = {"url": norm, "host": host, "befunde": [], "weiterleitung_zu": redirect_targets(norm),
                 "quellen": {source}}
        self.urls[norm] = entry
        try:
            ipaddress.ip_address(host)
            self.add_ip(host, "URL-Host")
            self.flag(entry, "MITTEL", "IP als Host", f"URL mit IP-Adresse als Host: {defang(host)}")
        except ValueError:
            pass
        checks = (
            ("xn--" in host, "MITTEL", "Punycode/IDN", f"Punycode-Domain: {defang(host)}"),
            (bool(host) and not host.isascii(), "HOCH", "Nicht-ASCII-Zeichen im Host", f"Nicht-ASCII-Host (Homograph?): {defang(host)}"),
            (p is not None and "@" in p.netloc, "HOCH", "Userinfo (@) im Host-Teil", f"URL mit '@' im Host-Teil: {defang_url(trunc(norm, 80))}"),
            (host in SHORTENERS, "MITTEL", "URL-Shortener", f"URL-Shortener: {defang(host)}"),
            (bool(port) and port not in (80, 443), "MITTEL", f"Port {port}", f"URL mit Nicht-Standard-Port {port}: {defang(host)}"),
            (p is not None and bool(DOWNLOAD_EXT_RE.search(p.path)), "MITTEL", "Datei-Download",
             f"URL verweist auf Datei-Download: {defang_url(trunc(norm, 100))}"),
        )
        for cond, level, short, text in checks:
            if cond:
                self.flag(entry, level, short, text)
        if entry["weiterleitung_zu"]:
            entry["befunde"].append("Weiterleitung")
        if _depth < 3:
            for target in entry["weiterleitung_zu"]:
                self.add_url(target, f"Weiterleitungsziel aus {host or '?'}", _depth + 1)

    def check_image(self, img, label):
        """Prüft ein <img> auf externes Nachladen und Tracking-Pixel.

        Parameter:
            img:   Attribute des <img>-Tags
            label: Fundstelle
        Schreibt: self.external_images, self.pixels (ab Score 2)
        """
        src = clean_url(img.get("src", ""))
        if not re.match(r"(?i)^(https?:)?//", src):
            return                                          # cid:/data: laden nichts nach
        score, reasons = pixel_score(img)
        self.external_images.append({"src": src, "quelle": label, "score": score})
        if score >= 2:
            self.pixels.append({"src": src, "quelle": label, "score": score, "gruende": reasons,
                                "bewertung": "wahrscheinlich" if score >= 3 else "moeglich"})

    def check_anchor(self, a, label):
        """Erkennt Links, deren angezeigter Text eine andere Domain zeigt als das tatsächliche Ziel.

        Redirect-Ziele (z. B. Safelinks) werden mit einbezogen, damit umgeschriebene Links nicht fälschlich auffallen.

        Parameter:
            a:     Link als dict {"href", "text"}
            label: Fundstelle
        Schreibt: self.mismatches, self.findings
        """
        href, text = clean_url(a.get("href", "")), " ".join(a.get("text", "").split())
        m = TEXT_IS_DOMAIN_RE.match(text) if text else None
        if not m or not re.match(r"(?i)^(https?:)?//|^www\.", href):
            return
        text_host, norm = m.group(1).lower().rstrip("."), normalize_url(href)
        targets = [t for t in [host_of(norm)] + [host_of(i) for i in redirect_targets(norm)] if t]
        if targets and not any(domains_related(text_host, t) for t in targets):
            self.mismatches.append({"quelle": label, "linktext": text, "ziel": norm})
            self.finding("MITTEL", f"Linktext '{defang(text_host)}' fuehrt tatsaechlich zu '{defang(targets[-1])}'")

    # ---------- Ausgaben

    def print_urls(self):
        """Gibt alle URLs entschärft aus, inkl. Befunden, Weiterleitungszielen und Fundstellen.

        Liest: self.urls, self.mismatches
        """
        section(f"URLs (entschaerft) - {len(self.urls)} eindeutig")
        if not self.urls:
            return print("  Keine URLs gefunden.")
        for e in sorted(self.urls.values(), key=lambda x: (x["host"], x["url"])):
            risky = [f for f in e["befunde"] if f != "Weiterleitung"]
            print(f"  {C.RED if risky else ''}{trunc(defang_url(e['url']), 150)}{C.RESET}")
            if e["befunde"]:
                print(f"    {C.YELLOW}! {', '.join(e['befunde'])}{C.RESET}")
            for target in e["weiterleitung_zu"]:
                print(f"    {C.CYAN}-> {trunc(defang_url(target), 140)}{C.RESET}")
            print(f"    {C.GREY}{trunc('; '.join(sorted(e['quellen'])), 140)}{C.RESET}")
        if self.mismatches:
            print(f"\n  {C.YELLOW}Linktext/Ziel-Abweichungen:{C.RESET}")
            for mm in self.mismatches:
                print(f"    '{trunc(mm['linktext'], 50)}' -> {trunc(defang_url(mm['ziel']), 100)}")

    def print_pixels(self):
        """Gibt Tracking-Pixel und sonstige externe Bilder aus.

        Liest: self.pixels, self.external_images
        Schreibt: self.findings (INFO bei erkannten Pixeln)
        """
        section("Tracking-Pixel und externe Bilder")
        if not self.external_images:
            return print("  Keine extern nachgeladenen Bilder gefunden.")
        kv("Externe Bilder", len(self.external_images))
        kv("Tracking-Pixel", len(self.pixels), C.RED if self.pixels else "")
        for px in self.pixels:
            print(f"\n  {C.RED}[{px['bewertung']}, Score {px['score']}]{C.RESET} {trunc(defang_url(px['src']), 130)}\n"
                  f"    {C.GREY}{', '.join(px['gruende'])} | {px['quelle']}{C.RESET}")
        if self.pixels:
            self.finding("INFO", f"{len(self.pixels)} Tracking-Pixel erkannt (Lesebestaetigung an Absender beim Nachladen)")
        others = [x for x in self.external_images if x["score"] < 2]
        if others:
            print(f"\n  {C.GREY}Weitere externe Bilder (Nachladen verraet ebenfalls die Oeffnung):{C.RESET}")
            for x in others[:15]:
                print(f"    {trunc(defang_url(x['src']), 130)}")
            if len(others) > 15:
                print(f"    ... {len(others) - 15} weitere")

    def domains(self):
        """Sammelt alle Domains aus URLs und E-Mail-Adressen (ohne IP-Hosts).

        Liest: self.urls, self.emails
        Rückgabe: sortierte Liste
        """
        d = {e.rsplit("@", 1)[1] for e in self.emails}
        for h in (e["host"] for e in self.urls.values() if e["host"]):
            try:
                ipaddress.ip_address(h)
            except ValueError:
                d.add(h)
        return sorted(d)

    def print_iocs(self):
        """Gibt IPs (mit Typ und Fundstellen), Domains und E-Mail-Adressen entschärft aus.

        Liest: self.ips, self.emails, self.urls (über domains())
        """
        section("IOCs")
        print(f"  {C.GREEN}IP-Adressen ({len(self.ips)}){C.RESET}")
        for ip, e in sorted(self.ips.items(), key=lambda x: (x[1]["typ"] != "Oeffentlich", x[0])):
            col = C.YELLOW if e["typ"] == "Oeffentlich" else C.GREY
            print(f"    {col}{ip:<40}{e['typ']:<12}{C.RESET}{C.GREY}{trunc(', '.join(sorted(e['quellen'])), 70)}{C.RESET}")
        for title, values in (("Domains", self.domains()), ("E-Mail-Adressen", sorted(self.emails))):
            print(f"\n  {C.GREEN}{title} ({len(values)}){C.RESET}")
            for v in values:
                print(f"    {defang(v)}")

    def analyze_x_headers(self):
        """Sammelt und zeigt alle X-Header (Mailer, Filter, Tracking-IDs).

        Liest: self.msg
        Schreibt: self.x_headers
        """
        try:
            items = list(self.msg.items())
        except Exception:
            items = list(self.msg.raw_items())
        self.x_headers = [{"name": k, "wert": " ".join(str(v).split())} for k, v in items if k.lower().startswith("x-")]
        section(f"X-Header ({len(self.x_headers)})")
        for x in self.x_headers:
            print(f"  {C.YELLOW}{x['name']}:{C.RESET} {trunc(x['wert'], 150)}")

    def print_findings(self):
        """Gibt alle Befunde sortiert nach Stufe aus (HOCH, MITTEL, INFO).

        Liest: self.findings, self.errors
        """
        section(f"BEFUNDE: {self.eml_path.name}")
        if not self.findings:
            print(f"  {C.GREEN}Keine Auffaelligkeiten durch Heuristiken erkannt.{C.RESET}")
        for f in sorted(self.findings, key=lambda x: LEVEL_ORDER[x["stufe"]]):
            print(f"  {color_of(f['stufe'])}[{f['stufe']:<6}]{C.RESET} {f['text']}")
        if self.errors:
            print(f"\n  {C.RED}Modulfehler: {len(self.errors)} (Details im Log){C.RESET}")

    def write_report(self):
        """Schreibt alle Ergebnisse als report.json (UTF-8) in den Fallordner.

        Liest: alle Ergebnis-Attribute
        Rückgabe: Pfad der Report-Datei
        """
        rep = {
            "tool": f"mailanalyzer {VERSION}", "ticket": self.ticket,
            "analysiert_am": datetime.now().isoformat(timespec="seconds"), "quelle": self.source,
            "header": self.header, "authentifizierung": self.auth, "m365_antispam": self.m365,
            "received_kette": self.received, "mime_struktur": self.mime, "bodies": self.bodies,
            "urls": [dict(e, quellen=sorted(e["quellen"])) for e in self.urls.values()],
            "linktext_mismatch": self.mismatches, "tracking_pixel": self.pixels,
            "externe_bilder": self.external_images, "formulare": self.forms,
            "smuggling_indikatoren": self.smuggling, "base64_funde": self.b64_hits,
            "iocs": {"ips": {ip: {"typ": e["typ"], "quellen": sorted(e["quellen"])} for ip, e in self.ips.items()},
                     "domains": self.domains(), "emails": sorted(self.emails)},
            "anhaenge": self.attachments, "x_header": self.x_headers,
            "befunde": sorted(self.findings, key=lambda x: LEVEL_ORDER[x["stufe"]]), "modulfehler": self.errors,
        }
        path = self.case_dir / "report.json"
        path.write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return path


# ------------------------------------------------------------------ Rahmen


def verify_saved(analyses, wait):
    """Prüft nach einer Wartezeit, ob Defender/AV gespeicherte Dateien entfernt oder verändert hat.

    Parameter:
        analyses: Liste der MailAnalysis-Objekte
        wait:     Wartezeit in Sekunden (aus --defender-wait)
    Schreibt: entry["status"] je Datei, Befunde der jeweiligen Mail
    """
    total = sum(len(a.saved) for a in analyses)
    if not total:
        return
    section(f"Abschlusspruefung Anhaenge ({total} Dateien, Wartezeit {wait:g} s fuer AV-Reaktion)")
    time.sleep(max(0.0, wait))
    for a in analyses:
        for entry, path in a.saved:
            if not path.exists():
                status, tag, text = "nach dem Schreiben entfernt (vermutlich Defender-Quarantaene)", "ENTFERNT", "entfernt"
            elif path.stat().st_size != entry["groesse"]:
                status, tag, text = "Groesse nach dem Schreiben veraendert (vermutlich AV-Bereinigung)", "VERAENDERT", "veraendert"
            else:
                entry["status"] = "vorhanden"
                print(f"  {C.GREEN}[OK]{C.RESET} {path}")
                continue
            entry["status"] = status
            a.finding("HOCH", f"'{entry['dateiname']}' nach dem Schreiben {text} (vermutlich AV)")
            print(f"  {C.RED}[{tag}]{C.RESET} {path}")


def collect_inputs(items):
    """Sammelt die zu analysierenden EML-Dateien aus Datei- und Ordnerangaben.

    Ordner werden nicht rekursiv nach *.eml durchsucht, .msg-Dateien abgelehnt, Duplikate entfernt.

    Parameter:
        items: Pfade aus der Kommandozeile
    Rückgabe: (Liste der Dateien, Liste der Fehlermeldungen)
    """
    files, errors = [], []
    for it in map(Path, items):
        if it.is_dir():
            found = sorted(x for x in it.iterdir() if x.is_file() and x.suffix.lower() == ".eml")
            files += found
            if not found:
                errors.append(f"Keine .eml-Dateien im Ordner: {it}")
        elif not it.is_file():
            errors.append(f"Nicht gefunden: {it}")
        elif it.suffix.lower() == ".msg":
            errors.append(f"MSG-Format wird nicht unterstuetzt (bitte als .eml speichern): {it}")
        else:
            if it.suffix.lower() != ".eml":
                print(f"{C.YELLOW}[!] Keine .eml-Endung, wird trotzdem als EML verarbeitet: {it}{C.RESET}")
            files.append(it)
    unique = {f.resolve(): f for f in reversed(files)}       # Duplikate entfernen, Reihenfolge behalten
    return [f for f in files if unique.get(f.resolve()) is f], errors


def main():
    r"""Einstiegspunkt: Argumente lesen, Ablage anlegen, alle EMLs analysieren, Reports schreiben.

    Kommandozeilen-Parameter:
        eingabe          EML-Datei(en) und/oder Ordner
        -t/--ticket      Ticketnummer (Pflicht, Teil des Ablagepfads)
        --base           Basisordner (Standard: C:\Analyse\Proben)
        --defender-wait  Wartezeit vor der AV-Prüfung in Sekunden
        --no-copy        Original-EML nicht kopieren
        --no-color       keine Farbausgabe
    Rückgabe: Exit-Code 0 (OK), 1 (Modulfehler), 2 (Eingabe-/Pfadfehler)
    """
    if os.name == "nt":
        os.system("")                                       # ANSI-Farben in der Windows-Konsole aktivieren
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")            # keine Abbrueche durch Sonderzeichen in der Konsole
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="Offline-Analyse von EML-Dateien (Phishing/Spam). Keine Netzwerkzugriffe.")
    ap.add_argument("eingabe", nargs="+", help="EML-Datei(en) und/oder Ordner mit *.eml")
    ap.add_argument("-t", "--ticket", required=True, help="Ticketnummer (Teil des Ablagepfads)")
    ap.add_argument("--base", default=DEFAULT_BASE, help=f"Basisordner (Standard: {DEFAULT_BASE})")
    ap.add_argument("--defender-wait", type=float, default=3.0,
                    help="Sekunden bis zur Pruefung, ob AV Dateien entfernt hat (Standard: 3)")
    ap.add_argument("--no-copy", action="store_true", help="Original-EML nicht in den Fallordner kopieren")
    ap.add_argument("--no-color", action="store_true", help="Farbausgabe deaktivieren")
    args = ap.parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    ticket = re.sub(r"[^A-Za-z0-9._-]", "_", args.ticket).strip("._")
    if not ticket:
        print(f"{C.RED}[X] Ungueltige Ticketnummer.{C.RESET}")
        return 2
    files, errs = collect_inputs(args.eingabe)
    for e in errs:
        print(f"{C.RED}[X] {e}{C.RESET}")
    if not files:
        return 2

    run_dir = Path(args.base) / f"{ticket}_{datetime.now():%Y%m%d-%H%M%S}"
    try:
        (run_dir / "Analyse").mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(run_dir / "mailanalyzer.log", encoding="utf-8")
    except OSError as e:
        print(f"{C.RED}[X] Ablage nicht anlegbar ({run_dir}): {e}{C.RESET}")
        return 2
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    print(f"{C.BOLD}mailanalyzer {VERSION}{C.RESET} | Ticket {ticket} | {len(files)} Datei(en) | Ablage {run_dir}")
    log.info("Start: Ticket %s, %d Datei(en)", ticket, len(files))

    analyses, used = [], set()
    for f in files:
        base = name = sanitize_name(f.stem, MAX_NAME_EML, "mail")
        i = 1
        while name.lower() in used:
            name, i = f"{base}_{i}", i + 1
        used.add(name.lower())
        case_dir = run_dir / "Analyse" / name
        try:
            (case_dir / "Anhaenge").mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"{C.RED}[X] Fallordner nicht anlegbar ({case_dir}): {e}{C.RESET}")
            continue
        a = MailAnalysis(f, case_dir, ticket)
        try:
            a.run(copy_original=not args.no_copy)
        except Exception as e:
            a.errors.append(f"Abbruch: {type(e).__name__}: {e}")
            log.exception("Abbruch bei %s", f)
            print(f"{C.RED}[X] {f.name}: {type(e).__name__}: {e}{C.RESET}")
        analyses.append(a)

    verify_saved(analyses, args.defender_wait)

    section("ZUSAMMENFASSUNG")
    for a in analyses:
        try:
            rp = a.write_report()
        except OSError as e:
            rp = f"FEHLER: {e}"
            a.errors.append(f"Report: {e}")
        hoch = sum(f["stufe"] == "HOCH" for f in a.findings)
        mittel = sum(f["stufe"] == "MITTEL" for f in a.findings)
        col = C.RED if hoch else (C.YELLOW if mittel else C.GREEN)
        print(f"  {col}{a.eml_path.name}{C.RESET}: HOCH {hoch} | MITTEL {mittel} | Dateien {len(a.saved)} | Report {rp}")
    print(f"\n  Ablage: {run_dir}\n  Log:    {run_dir / 'mailanalyzer.log'}\n  {C.GREY}Defender-Scan: "
          f"\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -Scan -ScanType 3 -File \"{run_dir / 'Analyse'}\"{C.RESET}")
    log.info("Ende")
    return 1 if any(a.errors for a in analyses) else 0


if __name__ == "__main__":
    sys.exit(main())
