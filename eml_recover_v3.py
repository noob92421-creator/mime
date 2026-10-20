#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eml_recover.py - exhaustive recovery of MIME content from malformed .eml files.

Every .eml file in --input is scanned by six strategies, from strict to forgiving.
All of them run on every file; later ones skip bytes that earlier ones already
recovered ("claimed spans").

  S1 standard_parser      Python's email parser with the lenient compat32 policy
  S2 boundary_recovery    declared + inferred boundaries, each segment parsed by hand
  S3 header_index         Content-Type list at the top, bodies below, paired in order
  S4 encoded_block_scan   line-structured base64 and quoted-printable blocks
  S5 base64_anchor_scan   base64 glued into other text, located by file signature
  S6 raw_signature_carve  already-decoded binary, carved out by magic bytes

Each candidate is typed by its file signature (signature wins over the declared
Content-Type, except zip/OLE subtypes and the text family), checked for
completeness, filtered (text residue, --min-size, --types), de-duplicated by
SHA-256 within its email, written as part_NNN.<ext>, and logged to a global
recovery_report.csv that is only ever appended to, so repeated cron runs are safe.

Usage:
    python3 eml_recover.py --input /path/Input/ --output /path/Output/ \
        [--min-size 1024] [--types pdf,jpg,png,docx,zip,other] [--no-magic]

Requires Python 3.8+. python-magic (libmagic) is optional.
"""

import argparse
import base64
import binascii
import bisect
import csv
import hashlib
import json
import logging
import mimetypes
import os
import quopri
import re
import shutil
import struct
import sys
import tempfile
import zlib
from collections import Counter
from email import message_from_bytes, message_from_string
from email.header import decode_header, make_header
from email.policy import compat32
from email.utils import collapse_rfc2231_value

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
MIN_SIZE = 1024                       # bytes; overridden by --min-size

EXTRACTED_DIR = "Extracted"
NOT_EXTRACTED_DIR = "Not Extracted"
REPORT_NAME = "recovery_report.csv"
CSV_COLUMNS = ["eml_name", "eml_destination", "extraction_method", "declared_type",
               "declared_filename", "detected_type", "encoding", "sha256", "status",
               "reason", "remark"]

# Residue check for text parts ("is this text really leaked email structure?")
RESIDUE_MIN_HEADER_LINES = 3          # distinct header lines, at least one MIME-ish
RESIDUE_B64_RUN_CHARS = 1024          # a swallowed base64 attachment
RESIDUE_SIZE_RATIO = 0.80             # share of the whole email
TEXT_PRINTABLE_RATIO = 0.95           # below this, bytes are not text

# Scanner tuning
B64_MIN_LINE_CHARS = 16               # S4: shortest line that can start a block
B64_MIN_BLOCK_CHARS = 64              # S4: shortest block worth decoding
B64_MIN_STRETCH_CHARS = 200           # S5: shortest unstructured base64 stretch
B64_MAX_ANCHOR_OFFSET = 96            # S5: how far into a stretch a file may start
TEXT_SAMPLE = 65536                   # bytes sampled for text checks

METHODS = ["standard_parser", "boundary_recovery", "header_index",
           "encoded_block_scan", "base64_anchor_scan", "raw_signature_carve"]
METHOD_RANK = {m: i for i, m in enumerate(METHODS)}

log = logging.getLogger("eml_recover")

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
TYPE_EXT = {
    "pdf": ".pdf", "png": ".png", "jpg": ".jpg", "gif": ".gif", "bmp": ".bmp",
    "tiff": ".tiff", "webp": ".webp", "psd": ".psd", "heic": ".heic", "avif": ".avif",
    "zip": ".zip", "docx": ".docx", "xlsx": ".xlsx", "pptx": ".pptx",
    "odt": ".odt", "ods": ".ods", "odp": ".odp",
    "doc": ".doc", "xls": ".xls", "ppt": ".ppt", "msg": ".msg", "ole": ".ole",
    "rar": ".rar", "7z": ".7z", "tar": ".tar", "gz": ".gz", "xz": ".xz", "bz2": ".bz2",
    "mp4": ".mp4", "mov": ".mov", "m4a": ".m4a", "3gp": ".3gp", "avi": ".avi",
    "mkv": ".mkv", "webm": ".webm", "mp3": ".mp3", "wav": ".wav", "flac": ".flac",
    "ogg": ".ogg", "rtf": ".rtf", "ps": ".ps", "exe": ".exe", "sqlite": ".sqlite",
    "html": ".html", "json": ".json", "xml": ".xml", "txt": ".txt",
    "other": ".bin",
}
BUILTIN_TYPES = set(TYPE_EXT)
TYPE_ALIASES = {"jpeg": "jpg", "jpe": "jpg", "tif": "tiff", "htm": "html",
                "text": "txt", "gzip": "gz", "tgz": "gz", "7zip": "7z", "qt": "mov",
                "m4v": "mp4"}
TEXT_TYPES = {"txt", "html", "json", "xml"}
ZIP_SUBTYPES = {"docx", "xlsx", "pptx", "odt", "ods", "odp"}
OLE_SUBTYPES = {"doc", "xls", "ppt", "msg"}
BOX_TYPES = {"mp4", "mov", "m4a", "3gp", "heic", "avif"}
RIFF_TYPES = {"wav", "webp", "avi"}

MIME_TO_TYPE = {
    "application/pdf": "pdf", "application/x-pdf": "pdf",
    "image/png": "png", "image/x-png": "png",
    "image/jpeg": "jpg", "image/jpg": "jpg", "image/pjpeg": "jpg",
    "image/gif": "gif", "image/bmp": "bmp", "image/x-ms-bmp": "bmp",
    "image/tiff": "tiff", "image/webp": "webp", "image/heic": "heic", "image/avif": "avif",
    "image/vnd.adobe.photoshop": "psd",
    "application/zip": "zip", "application/x-zip-compressed": "zip",
    "application/x-zip": "zip",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.oasis.opendocument.text": "odt",
    "application/vnd.oasis.opendocument.spreadsheet": "ods",
    "application/vnd.oasis.opendocument.presentation": "odp",
    "application/msword": "doc", "application/vnd.ms-word": "doc",
    "application/vnd.ms-excel": "xls", "application/excel": "xls",
    "application/vnd.ms-powerpoint": "ppt", "application/mspowerpoint": "ppt",
    "application/vnd.ms-outlook": "msg", "application/x-ole-storage": "ole",
    "application/x-cfb": "ole",
    "application/x-rar-compressed": "rar", "application/vnd.rar": "rar",
    "application/x-rar": "rar",
    "application/x-7z-compressed": "7z", "application/x-tar": "tar",
    "application/gzip": "gz", "application/x-gzip": "gz",
    "application/x-xz": "xz", "application/x-bzip2": "bz2",
    "video/mp4": "mp4", "video/quicktime": "mov", "audio/mp4": "m4a", "audio/x-m4a": "m4a",
    "video/3gpp": "3gp", "video/x-msvideo": "avi", "video/avi": "avi",
    "video/x-matroska": "mkv", "video/webm": "webm",
    "audio/mpeg": "mp3", "audio/mp3": "mp3", "audio/wav": "wav", "audio/x-wav": "wav",
    "audio/wave": "wav", "audio/vnd.wave": "wav", "audio/flac": "flac", "audio/x-flac": "flac",
    "audio/ogg": "ogg", "application/ogg": "ogg",
    "application/rtf": "rtf", "text/rtf": "rtf", "application/postscript": "ps",
    "application/x-msdownload": "exe", "application/x-dosexec": "exe",
    "application/vnd.microsoft.portable-executable": "exe",
    "application/x-sqlite3": "sqlite", "application/vnd.sqlite3": "sqlite",
    "text/html": "html", "application/xhtml+xml": "html",
    "application/json": "json", "text/json": "json",
    "text/xml": "xml", "application/xml": "xml",
    "text/plain": "txt",
}

OLE_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
RAR4_END = b"\xc4\x3d\x7b\x00\x40\x07\x00"
RAR5_END = b"\x1d\x77\x56\x51\x03\x05\x04\x00"

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
LINE_EOL_RE = re.compile(r"[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+")
LINE_RE = re.compile(r"[^\r\n]+")
B64_LINE_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]+")
B64_STRETCH_RE = re.compile(r"[A-Za-z0-9+/=\r\n]{%d,}" % B64_MIN_STRETCH_CHARS)
BLANK_LINE_RE = re.compile(r"\r?\n[ \t]*\r?\n|\r[ \t]*\r")
HEADER_LIKE_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,40}[ \t]*:")
BOUNDARY_PARAM_RE = re.compile(
    r"""boundary\s*=\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s;"']+))""", re.I)
DASH_LINE_RE = re.compile(r"^--([^\s]+?)(--)?[ \t]*\r?$", re.M)
QP_ESC_RE = re.compile(r"=[0-9A-F]{2}")
QP_SOFT_RE = re.compile(r"=\r?\n")
HEADER_LINE_RE = re.compile(
    r"^(content-type|content-transfer-encoding|content-disposition|mime-version|"
    r"from|to|cc|subject|date|received|message-id|return-path|reply-to)[ \t]*:",
    re.I | re.M)
MIME_HEADER_NAMES = {"content-type", "content-transfer-encoding", "content-disposition",
                     "mime-version", "received", "message-id", "return-path"}
LONG_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{%d,}" % RESIDUE_B64_RUN_CHARS)
PDF_OBJ_RE = re.compile(rb"\d+\s+\d+\s+obj")
RTF_TOKEN_RE = re.compile(rb"\\.|[{}]", re.S)
RAW_SIG_RE = re.compile(
    rb"%PDF-|\x89PNG\r\n\x1a\n|\xff\xd8\xff[\xc0-\xfe]|GIF8[79]a|"
    rb"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1|PK\x03\x04|Rar!\x1a\x07[\x00\x01]|"
    rb"7z\xbc\xaf\x27\x1c|\x1f\x8b\x08|\{\\rtf1|ustar[\x00 ]|"
    rb"ftyp(?:isom|iso[2-6]|mp4[12]|avc1|M4[AV] |qt  |3gp[0-9]|3g2a|heic|mif1|avif|dash|f4v )|"
    rb"RIFF[\s\S]{4}(?:WAVE|WEBP|AVI )|fLaC|OggS\x00|\x1aE\xdf\xa3|\xfd7zXZ\x00|"
    rb"BM[\s\S]{4}\x00\x00\x00\x00|ID3[\x02-\x04]\x00|MZ[\s\S]{58}")


def canonical_type(name):
    name = name.strip().lower().lstrip(".")
    return TYPE_ALIASES.get(name, name)


def declared_to_type(content_type, filename):
    """Map a declared Content-Type (or, failing that, a filename) to a type name."""
    t = MIME_TO_TYPE.get((content_type or "").lower())
    if t:
        return t
    if filename:
        ext = canonical_type(os.path.splitext(filename)[1])
        if ext in BUILTIN_TYPES and ext != "other":
            return ext
    return ""


# ---------------------------------------------------------------------------
# Signature sniffing
# ---------------------------------------------------------------------------
def sniff(d, strict=False):
    """Return the type whose signature starts `d`, or ''. strict=True drops weak
    2-byte signatures (used when scanning noise for file starts)."""
    if len(d) < 4:
        return ""
    h = d[:16]
    if h.startswith(b"%PDF-"):
        return "pdf"
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h.startswith(OLE_SIG):
        return "ole"
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        return "zip"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"\x1f\x8b\x08"):
        return "gz"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"BZh") and h[3:4].isdigit() and h[4:10] == b"1AY&SY":
        return "bz2"
    if h.startswith(b"{\\rtf"):
        return "rtf"
    if len(d) >= 262 and d[257:262] == b"ustar":
        return "tar"
    if d[4:8] == b"ftyp" and len(d) >= 12:
        brand = d[8:12]
        if brand == b"qt  ":
            return "mov"
        if brand in (b"M4A ", b"M4B "):
            return "m4a"
        if brand.startswith(b"3g"):
            return "3gp"
        if brand in (b"heic", b"heix", b"mif1", b"msf1"):
            return "heic"
        if brand == b"avif":
            return "avif"
        return "mp4"
    if h.startswith(b"RIFF") and len(d) >= 12:
        kind = d[8:12]
        if kind == b"WAVE":
            return "wav"
        if kind == b"WEBP":
            return "webp"
        if kind == b"AVI ":
            return "avi"
    if h.startswith(b"fLaC"):
        return "flac"
    if h.startswith(b"OggS\x00"):
        return "ogg"
    if h.startswith(b"\x1aE\xdf\xa3"):
        return "webm" if b"webm" in d[:64] else "mkv"
    if h.startswith(b"8BPS"):
        return "psd"
    if h.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if h.startswith(b"%!PS"):
        return "ps"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if h.startswith(b"ID3") and len(d) > 10 and d[3] < 5:
        return "mp3"
    if h.startswith(b"BM") and len(d) >= 26 and d[6:10] == b"\x00\x00\x00\x00" \
            and struct.unpack_from("<I", d, 14)[0] in (12, 40, 52, 56, 64, 108, 124):
        return "bmp"
    if h.startswith(b"MZ") and len(d) >= 0x40:
        e = struct.unpack_from("<I", d, 0x3C)[0]
        if e + 4 <= len(d) and d[e:e + 4] == b"PE\x00\x00":
            return "exe"
    if not strict and h[0] == 0xFF and h[1] in (0xFB, 0xF3, 0xF2, 0xFA):
        return "mp3"
    return ""


def zip_entries(d, limit=4000):
    """(name, data_offset) for every ZIP local file header; works on truncated ZIPs."""
    out, pos = [], 0
    while len(out) < limit:
        i = d.find(b"PK\x03\x04", pos)
        if i < 0 or i + 30 > len(d):
            break
        nlen, xlen = struct.unpack_from("<HH", d, i + 26)
        out.append((d[i + 30:i + 30 + nlen], i + 30 + nlen + xlen))
        pos = i + 4
    return out


def refine_zip(d, declared):
    if declared in ZIP_SUBTYPES:
        return declared
    entries = zip_entries(d)
    for name, off in entries:
        if name == b"mimetype":
            mt = d[off:off + 80]
            if b"opendocument.text" in mt:
                return "odt"
            if b"opendocument.spreadsheet" in mt:
                return "ods"
            if b"opendocument.presentation" in mt:
                return "odp"
    for name, _ in entries:
        if name.startswith(b"word/"):
            return "docx"
        if name.startswith(b"xl/"):
            return "xlsx"
        if name.startswith(b"ppt/"):
            return "pptx"
    return "zip"


def refine_ole(d, declared):
    if declared in OLE_SUBTYPES:
        return declared
    for name, t in (("__substg1.0_", "msg"), ("WordDocument", "doc"),
                    ("PowerPoint Document", "ppt"), ("Workbook", "xls"), ("Book", "xls")):
        if name.encode("utf-16-le") in d:
            return t
    return "ole"


# ---------------------------------------------------------------------------
# End finders: return the length of the complete file at the start of `d`,
# or None when the end is missing (truncated).
# ---------------------------------------------------------------------------
def _eol_after(d, e):
    if d[e:e + 2] == b"\r\n":
        return e + 2
    if d[e:e + 1] in (b"\r", b"\n"):
        return e + 1
    return e


def end_pdf(d):
    i = d.rfind(b"%%EOF")
    return None if i < 0 else _eol_after(d, i + 5)


def end_png(d):
    pos, n = 8, len(d)
    while pos + 8 <= n:
        ln = struct.unpack_from(">I", d, pos)[0]
        typ = d[pos + 4:pos + 8]
        if not typ.isalpha():
            return None
        pos += 12 + ln
        if typ == b"IEND":
            return pos if pos <= n else None
    return None


def end_jpg(d):
    pos, n = 2, len(d)
    while pos < n:
        if d[pos] != 0xFF:
            return None
        while pos < n and d[pos] == 0xFF:
            pos += 1
        if pos >= n:
            return None
        m = d[pos]
        pos += 1
        if m == 0xD9:
            return pos
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            continue
        if pos + 2 > n:
            return None
        ln = struct.unpack_from(">H", d, pos)[0]
        if ln < 2 or pos + ln > n:
            return None
        pos += ln
        if m == 0xDA:                      # entropy-coded scan data follows
            while True:
                j = d.find(b"\xff", pos)
                if j < 0 or j + 1 >= n:
                    return None
                nb = d[j + 1]
                if nb == 0x00 or 0xD0 <= nb <= 0xD7 or nb == 0xFF:
                    pos = j + 1
                    continue
                pos = j
                break
    return None


def _gif_subblocks(d, pos):
    n = len(d)
    while pos < n:
        sz = d[pos]
        pos += 1
        if sz == 0:
            return pos
        pos += sz
    return None


def end_gif(d):
    n = len(d)
    if n < 13:
        return None
    flags, pos = d[10], 13
    if flags & 0x80:
        pos += 3 * (2 << (flags & 7))
    while pos is not None and pos < n:
        b = d[pos]
        if b == 0x3B:
            return pos + 1
        if b == 0x21:
            pos = _gif_subblocks(d, pos + 2)
        elif b == 0x2C:
            if pos + 10 > n:
                return None
            f = d[pos + 9]
            pos += 10
            if f & 0x80:
                pos += 3 * (2 << (f & 7))
            pos = _gif_subblocks(d, pos + 1)
        else:
            return None
    return None


def end_zip(d):
    """End of the ZIP starting at d[0]: the first end-of-central-directory record
    whose directory offset + size point back to it (so two ZIPs back to back are
    split correctly); falls back to the last record (self-extractors, prefixes)."""
    last, pos = None, 0
    while True:
        i = d.find(b"PK\x05\x06", pos)
        if i < 0 or i + 22 > len(d):
            break
        cd_size, cd_off, clen = struct.unpack_from("<IIH", d, i + 12)
        e = i + 22 + clen
        if e <= len(d):
            if cd_off + cd_size == i or (cd_off == 0xFFFFFFFF and d.rfind(b"PK\x06\x06", 0, i) >= 0):
                return e
            last = e
        pos = i + 4
    return last


def end_7z(d):
    if len(d) < 32:
        return None
    off, size = struct.unpack_from("<QQ", d, 12)
    if off > 1 << 40 or size > 1 << 40:
        return None
    e = 32 + off + size
    return e if e <= len(d) else None


def _tar_size(field):
    if field[0] & 0x80:                        # base-256 for huge members
        return int.from_bytes(field[1:], "big")
    s = field.strip(b" \x00")
    return int(s, 8) if s else 0


def end_tar(d):
    pos, n = 0, len(d)
    while pos + 512 <= n:
        blk = d[pos:pos + 512]
        if blk.count(0) == 512:
            zeros = 0
            while pos + 512 <= n and d[pos:pos + 512].count(0) == 512:
                pos += 512
                zeros += 1
            return pos if zeros >= 2 else None
        try:
            size = _tar_size(blk[124:136])
        except ValueError:
            return None
        pos += 512 + ((size + 511) // 512) * 512
    return None


def end_gz(d):
    o = zlib.decompressobj(31)
    buf = d
    try:
        while True:
            o.decompress(buf, 1 << 20)
            if o.eof:
                return len(d) - len(o.unused_data)
            buf = o.unconsumed_tail
            if not buf:
                return None
    except zlib.error:
        return None


BOX_TOP = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"moof",
           b"mfra", b"pdin", b"styp", b"sidx", b"ssix", b"prft", b"emsg", b"udta", b"pnot",
           b"PICT", b"junk", b"jP  ", b"mvhd", b"trak", b"hoov", b"pict", b"iinf", b"iloc",
           b"idat", b"iprp", b"pitm", b"iref", b"ipro", b"dinf", b"hdlr"}


def end_box(d):
    pos, n = 0, len(d)
    while pos + 8 <= n:
        size = struct.unpack_from(">I", d, pos)[0]
        typ = d[pos + 4:pos + 8]
        if typ not in BOX_TOP:
            break
        hdr = 8
        if size == 1:
            if pos + 16 > n:
                return None
            size, hdr = struct.unpack_from(">Q", d, pos + 8)[0], 16
        elif size == 0:
            return n
        if size < hdr:
            break
        if pos + size > n:
            return None
        pos += size
    return pos or None


def end_riff(d):
    if len(d) < 12:
        return None
    e = 8 + struct.unpack_from("<I", d, 4)[0]
    return e if e <= len(d) else None


def end_bmp(d):
    size = struct.unpack_from("<I", d, 2)[0] if len(d) >= 6 else 0
    return size if 26 <= size <= len(d) else None


def end_ole(d):
    """Size from the FAT: highest sector in use, plus the header sector."""
    if len(d) < 512:
        return None
    shift = struct.unpack_from("<H", d, 0x1E)[0]
    if shift not in (9, 12):
        return None
    ssz = 1 << shift
    n_fat = struct.unpack_from("<I", d, 0x2C)[0]
    difat_next, n_difat = struct.unpack_from("<II", d, 0x44)
    fat_secs = [s for s in struct.unpack_from("<109I", d, 0x4C) if s < 0xFFFFFFFA]
    guard = 0
    while n_difat and difat_next < 0xFFFFFFFA and guard < 10000:
        off = (difat_next + 1) * ssz
        if off + ssz > len(d):
            return None
        entries = struct.unpack_from("<%dI" % (ssz // 4), d, off)
        fat_secs.extend(s for s in entries[:-1] if s < 0xFFFFFFFA)
        difat_next = entries[-1]
        guard += 1
    fat_secs = fat_secs[:n_fat]
    if not fat_secs:
        return None
    per = ssz // 4
    max_sec = -1
    for k, fs in enumerate(fat_secs):
        off = (fs + 1) * ssz
        if off + ssz > len(d):
            return None
        entries = struct.unpack_from("<%dI" % per, d, off)
        for i in range(per - 1, -1, -1):
            if entries[i] != 0xFFFFFFFF:
                max_sec = max(max_sec, k * per + i)
                break
    if max_sec < 0:
        return None
    e = (max_sec + 2) * ssz
    return e if e <= len(d) else None


def end_rar(d):
    marker = RAR5_END if d[6:8] == b"\x01\x00" else RAR4_END
    i = d.find(marker, 7)
    return None if i < 0 else i + len(marker)


def end_rtf(d):
    depth = 0
    for m in RTF_TOKEN_RE.finditer(d):
        tok = m.group()
        if tok == b"{":
            depth += 1
        elif tok == b"}":
            depth -= 1
            if depth == 0:
                return _eol_after(d, m.end())
    return None


END_FINDERS = {"pdf": end_pdf, "png": end_png, "jpg": end_jpg, "gif": end_gif,
               "zip": end_zip, "7z": end_7z, "tar": end_tar, "gz": end_gz,
               "bmp": end_bmp, "rar": end_rar, "rtf": end_rtf, "ole": end_ole}
END_FINDERS.update({t: end_zip for t in ZIP_SUBTYPES})
END_FINDERS.update({t: end_ole for t in OLE_SUBTYPES})
END_FINDERS.update({t: end_box for t in BOX_TYPES})
END_FINDERS.update({t: end_riff for t in RIFF_TYPES})


def carve_plausible(t, d):
    """Extra checks before carving raw bytes, to avoid carving noise."""
    if t == "pdf":
        return PDF_OBJ_RE.search(d[:8192]) is not None
    if t == "zip":
        ver, = struct.unpack_from("<H", d, 4) if len(d) >= 30 else (99,)
        nlen = struct.unpack_from("<H", d, 26)[0] if len(d) >= 30 else 0
        return ver <= 63 and 0 < nlen < 1024
    if t == "gz":
        try:
            zlib.decompressobj(31).decompress(d[:4096], 64)
            return True
        except zlib.error:
            return False
    if t == "jpg":
        return len(d) > 4 and (0xE0 <= d[3] <= 0xEF or d[3] in (0xDB, 0xC0, 0xC2, 0xC4, 0xFE))
    if t == "ole":
        return d[0x1C:0x1E] == b"\xfe\xff"
    if t == "tar":
        return d[:1] not in (b"\x00", b"") and d[0:1].isascii()
    return True


# ---------------------------------------------------------------------------
# Optional libmagic
# ---------------------------------------------------------------------------
_MAGIC = None          # callable: bytes -> MIME type string


def _magic_backend():
    """Return (detect, name) for whichever libmagic binding provides `import magic`.
    Three different packages install a module called `magic`:
      python-magic  (pip install python-magic)           magic.Magic(mime=True).from_buffer
      file-magic    (apt install python3-magic, or pip install file-magic; libmagic's own)
                                                         magic.detect_from_content(b).mime_type
      filemagic     (pip install filemagic, old)         magic.Magic(flags=...).id_buffer
    """
    import magic  # noqa: WPS433
    if hasattr(magic, "from_buffer"):
        try:
            return magic.Magic(mime=True).from_buffer, "python-magic"
        except TypeError:
            pass
    if hasattr(magic, "detect_from_content"):
        return (lambda b: magic.detect_from_content(b).mime_type), "file-magic"
    if hasattr(magic, "Magic") and hasattr(magic, "MAGIC_MIME_TYPE"):
        m = magic.Magic(flags=magic.MAGIC_MIME_TYPE)
        return m.id_buffer, "filemagic"
    raise ImportError("the 'magic' module at %s is not a libmagic binding"
                      % getattr(magic, "__file__", "?"))


def _magic_hint(exc):
    msg = str(exc).lower()
    py = sys.executable or "python3"
    if isinstance(exc, ModuleNotFoundError) or "no module named" in msg:
        return ("no 'magic' module for this interpreter (%s). Install it into THIS Python: "
                "%s -m pip install python-magic. Under cron, use the same absolute "
                "python path in the crontab." % (py, py))
    if "not a libmagic binding" in msg:
        return ("a different package named 'magic' is installed. Run: %s -m pip uninstall -y "
                "magic libmagic && %s -m pip install python-magic" % (py, py))
    if "magic file" in msg or "magic files" in msg or "magic.mgc" in msg:
        return ("libmagic loads but its database (magic.mgc) is missing. Debian/Ubuntu: apt "
                "install libmagic-mgc; RHEL/Rocky/Fedora: dnf install file-libs; or point the "
                "MAGIC environment variable at a magic.mgc file.")
    if "libmagic" in msg or isinstance(exc, OSError):
        return ("the libmagic shared library was not found. Debian/Ubuntu: apt install libmagic1; "
                "RHEL/Rocky/Fedora: dnf install file-libs; Alpine: apk add libmagic; "
                "macOS: brew install libmagic; Windows: pip install python-magic-bin.")
    return "unexpected error; run with --check-magic for details."


def init_magic(disabled, verbose=False):
    """Load libmagic and prove it works on a real buffer. Returns a status string."""
    global _MAGIC
    _MAGIC = None
    if disabled:
        return "off (--no-magic)"
    try:
        detect, name = _magic_backend()
        probe = detect(b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n")
        if isinstance(probe, bytes):
            probe = probe.decode("ascii", "replace")
        if not probe or "pdf" not in probe.lower():
            raise RuntimeError("libmagic returned %r for a PDF test buffer; its magic database "
                               "looks broken (magic files)" % (probe,))
    except Exception as exc:
        log.warning("libmagic unavailable, continuing with built-in signatures only. "
                    "Cause: %s: %s. Fix: %s", type(exc).__name__, exc, _magic_hint(exc))
        return "off (unavailable: %s)" % type(exc).__name__

    def detect_mime(b):
        out = detect(b)
        return out.decode("ascii", "replace") if isinstance(out, bytes) else out

    _MAGIC = detect_mime
    if verbose:
        import magic  # noqa: WPS433
        log.info("libmagic OK via %s (%s), python %s", name,
                 getattr(magic, "__file__", "?"), sys.executable)
    return "on (%s)" % name


def magic_type(d):
    if _MAGIC is None:
        return ""
    try:
        mime = _MAGIC(d[:262144])
    except Exception as exc:
        log.debug("libmagic failed on a buffer: %s", exc)
        return ""
    mime = (mime or "").split(";")[0].strip().lower()
    if mime in ("", "application/octet-stream", "application/x-empty", "text/plain",
                "data", "inode/x-empty"):
        return ""
    t = MIME_TO_TYPE.get(mime)
    if t:
        return t
    ext = mimetypes.guess_extension(mime)
    return ext.lstrip(".").lower() if ext else ""


# ---------------------------------------------------------------------------
# Text handling
# ---------------------------------------------------------------------------
def decode_text(d, charset=None):
    if d.startswith(b"\xef\xbb\xbf"):
        encs = ["utf-8-sig"]
    elif d[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encs = ["utf-16"]
    elif charset in ("utf-16-le", "utf-16-be"):
        encs = [charset]
    else:
        encs = [charset, "utf-8", "cp1252", "latin-1"]
    for enc in encs:
        if not enc:
            continue
        try:
            return d.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return d.decode("latin-1")


def utf16_without_bom(sample):
    """'utf-16-le' / 'utf-16-be' when mostly-ASCII text is stored as UTF-16 without
    a byte-order mark (every other byte is zero), else None."""
    n = len(sample) // 2 * 2
    if n < 16:
        return None
    even, odd = sample[0:n:2], sample[1:n:2]
    if odd.count(0) >= 0.9 * len(odd) and even.count(0) <= 0.1 * len(even):
        return "utf-16-le"
    if even.count(0) >= 0.9 * len(even) and odd.count(0) <= 0.1 * len(odd):
        return "utf-16-be"
    return None


def text_of(d, charset=None):
    """Decoded text if `d` looks like text, else None."""
    if not d:
        return None
    sample = d[:TEXT_SAMPLE]
    if b"\x00" in sample and sample[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        charset = utf16_without_bom(sample)
        if charset is None:
            return None
    s = decode_text(sample, charset)
    if not s:
        return None
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t\f")
    if printable / len(s) < TEXT_PRINTABLE_RATIO:
        return None
    return decode_text(d, charset) if len(d) > TEXT_SAMPLE else s


HTML_DOC_RE = re.compile(r"<!doctype\s+html|<html[\s>]", re.I)
# common HTML tags, all-lowercase or all-uppercase; XML such as <Body> or <Head>
# (SOAP, invoices) is mixed case and does not match
HTML_TAG_RE = re.compile(
    r"<(?:head|body|div|p|br|hr|table|tr|td|th|span|a|img|font|ul|ol|li|h[1-6]|b|i|u|"
    r"strong|em|center|style|meta|title|blockquote|pre)[\s>/]|"
    r"<(?:HEAD|BODY|DIV|P|BR|HR|TABLE|TR|TD|TH|SPAN|A|IMG|FONT|UL|OL|LI|H[1-6]|B|I|U|"
    r"STRONG|EM|CENTER|STYLE|META|TITLE|BLOCKQUOTE|PRE)[\s>/]")
XML_PARSE_LIMIT = 8 * 1024 * 1024


def is_wellformed_xml(st):
    if len(st) > XML_PARSE_LIMIT or "<!ENTITY" in st[:65536]:
        return False
    import xml.etree.ElementTree as ET  # noqa: WPS433
    try:
        ET.fromstring(st.encode("utf-8"))
        return True
    except (ET.ParseError, ValueError):
        return False


def json_kind(st):
    """'json', 'partial' (truncated JSON), 'lines' (JSON Lines) or ''."""
    body = st.rstrip()
    try:
        json.loads(body)
        return "json"
    except ValueError as exc:
        pos = getattr(exc, "pos", 0) or 0
        if st[:1] in "{[" and body and pos >= 0.9 * len(body):
            return "partial"
    lines = [l for l in body.splitlines() if l.strip()]
    if len(lines) >= 2 and lines[0].lstrip()[:1] in "{[":
        try:
            for l in lines[:500]:
                json.loads(l)
            return "lines"
        except ValueError:
            pass
    return ""


def classify_text(s, declared):
    """Return (type, partial) for decoded text."""
    st = s.lstrip("\ufeff \t\r\n")
    head = st[:4096]

    def html():
        whole = st.lower()
        return "html", ("<html" in whole and "</html>" not in whole)

    if st.startswith("<?xml"):                       # XML prolog, unless it is XHTML
        return html() if HTML_DOC_RE.search(head) else ("xml", False)
    if declared == "xml" and st.startswith("<"):
        return "xml", False
    if HTML_DOC_RE.search(head) or (st.startswith("<") and HTML_TAG_RE.search(head)):
        return html()
    if declared == "html" and re.search(r"<\s*[a-zA-Z!/]", head):
        return html()
    if st[:1] in "{[" or declared == "json":
        kind = json_kind(st)
        if kind:
            return "json", kind == "partial"
    if st.startswith("<") and st.rstrip().endswith(">") and is_wellformed_xml(st):
        return "xml", False
    return "txt", False


# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------
class OffsetMap(object):
    """Maps an index in a joined base64 string back to a byte offset in the file."""

    def __init__(self):
        self.starts, self.raws, self.lens, self.total = [], [], [], 0

    def add(self, raw_pos, length):
        self.starts.append(self.total)
        self.raws.append(raw_pos)
        self.lens.append(length)
        self.total += length

    def raw(self, idx):
        if not self.starts:
            return None
        if idx >= self.total:
            return self.raws[-1] + self.lens[-1]
        i = bisect.bisect_right(self.starts, idx) - 1
        return self.raws[i] + (idx - self.starts[i])


def b64_decode_region(text, a, b, strict_lengths=True):
    """Tolerant base64 decode of text[a:b].
    Returns (data, cut, offset_map, notes). `cut` is True when the stream stopped
    mid-quantum without padding. With strict_lengths, lines whose length differs
    from the block's usual line length (junk injected mid-block) are dropped."""
    pieces = []
    for m in LINE_EOL_RE.finditer(text, a, b):
        line = m.group()
        s = line.strip()
        if not s:
            if pieces:
                break                    # a blank line ends a base64 body
            continue
        start = m.start() + len(line) - len(line.lstrip())
        if B64_LINE_RE.fullmatch(s):
            pieces.append((start, s))
        elif not strict_lengths:
            pm = B64_LINE_RE.match(s)
            if pm and pieces or pm and len(pm.group()) >= 4:
                pieces.append((start, pm.group()))
            break                        # text glued after the base64 ends the stream
    notes = []
    if strict_lengths and len(pieces) >= 3:
        common = Counter(len(s) for _, s in pieces[:-1]).most_common(1)[0][0]
        kept = []
        for i, (pos, s) in enumerate(pieces):
            if len(s) == common or ((i == len(pieces) - 1 or s.endswith("=")) and len(s) < common):
                kept.append((pos, s))
        if len(kept) < len(pieces):
            notes.append("dropped %d junk line(s) inside base64" % (len(pieces) - len(kept)))
        pieces = kept
    omap = OffsetMap()
    chars = []
    padded = False
    for pos, s in pieces:
        k = s.find("=")
        if k >= 0:
            s = s[:k]
            padded = True
        if s:
            omap.add(pos, len(s))
            chars.append(s)
        if padded:
            break
    joined = "".join(chars)
    cut = False
    rem = len(joined) % 4
    if rem == 1:
        joined = joined[:-1]
        cut = True
    elif rem and not padded:
        cut = True
    if len(joined) % 4:
        joined += "=" * (4 - len(joined) % 4)
    try:
        data = base64.b64decode(joined)
    except (binascii.Error, ValueError):
        return b"", True, omap, notes + ["base64 decode error"]
    return data, cut, omap, notes


def looks_base64(body, strict):
    """Is this body base64 text? strict=True when no CTE was declared."""
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    if not lines:
        return False
    good = sum(1 for l in lines if B64_LINE_RE.fullmatch(l))
    total = sum(len(l) for l in lines)
    if good / len(lines) < (0.9 if strict else 0.6):
        return False
    if strict:
        if not (B64_LINE_RE.fullmatch(lines[0]) and len(lines[0]) >= B64_MIN_LINE_CHARS):
            return False
        joined = "".join(lines)
        return total >= 64 and re.search(r"[0-9+/]", joined) is not None \
            and max(len(l) for l in lines) >= B64_MIN_LINE_CHARS
    return total >= 4


def mostly_ascii_text(s, ratio=0.97):
    if not s:
        return False
    sample = s[:TEXT_SAMPLE]
    good = sum(1 for ch in sample if " " <= ch <= "~" or ch in "\r\n\t")
    return good / len(sample) >= ratio


def looks_qp(body):
    """Quoted-printable needs soft line breaks or =3D, and no escaped letters or
    digits (encoders never escape those); 'TIMEOUT=30' or 'PORT=20' is plain text."""
    if not mostly_ascii_text(body):
        return False
    escapes = QP_ESC_RE.findall(body)
    if len(escapes) < 2:             # base64 padding ("==" at a line end) is not QP
        return False
    if QP_SOFT_RE.search(body) is None and "=3D" not in body:
        return False
    return not any(int(e[1:], 16) < 0x80 and chr(int(e[1:], 16)).isalnum() for e in escapes)


def undeclared_b64_ok(text, a, b):
    """Undeclared base64 is accepted only if it decodes to a known file signature or
    to clean UTF-8 text; hex hashes or IDs also fit the base64 alphabet."""
    data, _cut, _omap, _notes = b64_decode_region(text, a, b)
    if not data:
        return False
    if sniff(data, strict=True) or b64_nested(data) is not None:
        return True
    try:
        s = data[:TEXT_SAMPLE].decode("utf-8")
    except UnicodeDecodeError:
        try:   # the sample may end inside a multi-byte character
            s = data[:TEXT_SAMPLE - 3].decode("utf-8")
        except UnicodeDecodeError:
            return False
    good = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t\f")
    return bool(s) and good / len(s) >= TEXT_PRINTABLE_RATIO


def b64_nested(data):
    """If decoded data is itself base64 of a known file, decode once more."""
    if len(data) < 64 or data[:1] not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":
        return None
    try:
        s = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not looks_base64(s, strict=True):
        return None
    inner, _, _, _ = b64_decode_region(s, 0, len(s))
    return inner if sniff(inner, strict=True) else None


# ---------------------------------------------------------------------------
# Candidates and per-email context
# ---------------------------------------------------------------------------
class Candidate(object):
    def __init__(self, data, method, encoding, declared_type="", declared_filename="",
                 src=None, omap=None, cut=False, role="attachment", charset=None,
                 notes=None):
        self.data = data
        self.method = method
        self.encoding = encoding
        self.declared_type = declared_type or ""
        self.declared_filename = declared_filename or ""
        self.src = src                  # (start, end) of the encoded source in the file
        self.omap = omap                # OffsetMap for base64 sources
        self.cut = cut                  # evidence the source stream was cut short
        self.role = role
        self.charset = charset
        self.notes = list(notes or [])
        self.lead = 0                   # junk bytes skipped before a file header
        self.detected_type = ""
        self.partial = False
        self.status = ""
        self.reason = ""
        self.sha256 = ""
        self.out_name = ""
        self.kept_ref = None            # the kept candidate this duplicates
        self.text = None
        self.whole_body = False         # whole message body taken as one part (S1 fallback)
        self.multipart_fallback = False # ...of a multipart message the parser could not split
        self.trimmed = 0                # non-blank bytes cut after the file's end marker
        self.claimed = None             # span this candidate claimed in the file

    @property
    def position(self):
        return self.src[0] if self.src else 1 << 60


class Ctx(object):
    def __init__(self, raw, name):
        self.raw = raw
        self.name = name
        self.text = raw.decode("latin-1")
        self.size = len(raw)
        self.claims = []                # sorted, merged (start, end) spans
        self.candidates = []
        self.boundaries = set()
        self.boundary_lines = []        # (line_start, line_end, token, closing)
        self.has_structure = False

    # -- claims ----------------------------------------------------------------
    def claim(self, a, b):
        if a is None or b is None or b <= a:
            return
        spans = self.claims + [(a, b)]
        spans.sort()
        merged = [spans[0]]
        for s, e in spans[1:]:
            if s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        self.claims = merged

    def overlaps(self, a, b):
        return any(s < b and a < e for s, e in self.claims)

    def claimed_at(self, pos):
        return any(s <= pos < e for s, e in self.claims)

    def gaps(self, a=0, b=None):
        b = self.size if b is None else b
        out, cur = [], a
        for s, e in self.claims:
            if e <= cur:
                continue
            if s >= b:
                break
            if s > cur:
                out.append((cur, s))
            cur = max(cur, e)
        if cur < b:
            out.append((cur, b))
        return out

    def next_boundary_after(self, pos):
        for ls, _le, _t, _c in self.boundary_lines:
            if ls > pos:
                return ls
        return None

    # -- adding a candidate ----------------------------------------------------
    def add(self, c):
        evaluate(c, self)
        self.candidates.append(c)
        if c.status:                     # rejected already (residue, decode failure)
            return c
        if is_fallback(c):
            return c                     # fallbacks never block later strategies
        self._claim_source(c)
        return c

    def _claim_source(self, c):
        if not c.src:
            return
        a, b = c.src
        if c.encoding == "raw":
            span = (a + c.lead, a + c.lead + len(c.data))
        elif c.encoding == "base64" and c.omap is not None and "decoded twice" not in c.notes:
            need = -(-(len(c.data) + c.lead) // 3) * 4
            end = c.omap.raw(need)
            if end is None:
                return
            while end < len(self.text) and self.text[end] == "=":
                end += 1
            span = (a, max(end, a + 1))
        else:
            span = (a, b)
        c.claimed = span
        self.claim(*span)


def is_fallback(c):
    """Candidates that must not block later strategies and are dropped when a real
    part is found inside them: unknown bytes, a multipart message the parser could
    not split, and a whole-message body that is text or is not one clean file (junk
    before its signature, or a lot of data after its end)."""
    if c.detected_type == "other" or c.multipart_fallback:
        return True
    return c.whole_body and (c.detected_type in TEXT_TYPES or c.lead > 0 or c.trimmed > 64)


def evaluate(c, ctx):
    """Detect type, trim to the real end, decide completeness, run the residue check."""
    d = c.data
    if not d:
        c.status, c.reason = "decode_failed", "decoded to zero bytes"
        return
    declared_t = declared_to_type(c.declared_type, c.declared_filename)
    t = sniff(d)
    if not t:
        i = d.find(b"%PDF-", 0, 1024)
        if i > 0:
            d, c.lead, t = d[i:], i, "pdf"
            c.notes.append("skipped %d junk bytes before PDF header" % i)
    if t == "zip":
        t = refine_zip(d, declared_t)
    elif t == "ole":
        t = refine_ole(d, declared_t)

    if t:
        finder = END_FINDERS.get(t)
        if finder:
            try:
                e = finder(d)
            except (struct.error, IndexError, ValueError):
                e = None
            if e is None:
                c.partial = True
                c.notes.append("end of %s not found" % t)
            else:
                if e < len(d):
                    tail = d[e:]
                    if tail.strip(b"\r\n\t \x00"):
                        c.notes.append("trimmed %d trailing bytes" % len(tail))
                        c.trimmed = len(tail)
                    d = d[:e]
                c.partial = False
        else:
            c.partial = c.cut
    else:
        s = text_of(d, c.charset)
        if s is not None:
            t, part = classify_text(s, declared_t)
            c.text = s
            c.partial = part or c.cut
        else:
            t = magic_type(d) or "other"
            c.partial = c.cut

    c.data = d
    c.detected_type = t
    c.sha256 = hashlib.sha256(d).hexdigest()
    if c.role == "body":
        c.notes.append("body")
    if declared_t and declared_t != t:
        c.notes.append("declared %s, detected %s" % (declared_t, t))
    if t in TEXT_TYPES:
        why = residue_reason(c, ctx)
        if why:
            c.status, c.reason = "mime_residue", why


def residue_reason(c, ctx):
    s = c.text if c.text is not None else decode_text(c.data, c.charset)
    names = set(m.group(1).lower() for m in HEADER_LINE_RE.finditer(s[:200000]))
    if c.whole_body and names & {"content-type", "content-transfer-encoding", "content-disposition"}:
        return "whole message body containing part headers (%s)" % ", ".join(sorted(names))
    if len(names) >= RESIDUE_MIN_HEADER_LINES and names & MIME_HEADER_NAMES:
        return "contains %d email header lines (%s)" % (len(names), ", ".join(sorted(names)))
    for tok in ctx.boundaries:
        if re.search(r"^--" + re.escape(tok), s, re.M | re.I):
            return "contains boundary line --%s" % tok
    part_headers = names & {"content-type", "content-transfer-encoding", "content-disposition"}
    if (c.whole_body or part_headers) and \
            (LONG_B64_RUN_RE.search(s) or find_b64_blocks(s, 0, len(s), RESIDUE_B64_RUN_CHARS)):
        return "contains MIME part headers and a base64 run of %d+ chars" % RESIDUE_B64_RUN_CHARS
    if c.whole_body and ctx.has_structure and len(c.data) >= RESIDUE_SIZE_RATIO * ctx.size:
        return "is %d%% of the whole email" % (100 * len(c.data) // max(ctx.size, 1))
    return ""


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------
def header_filename(msg):
    fn = None
    try:
        fn = msg.get_filename()
    except Exception:
        fn = None
    if not fn:
        try:
            fn = msg.get_param("name")
            if isinstance(fn, tuple):
                fn = collapse_rfc2231_value(fn)
        except Exception:
            fn = None
    if not fn:
        return ""
    fn = str(fn)
    try:
        fn = str(make_header(decode_header(fn)))
    except Exception:
        pass
    return re.sub(r"[\r\n\t]+", " ", fn).strip().strip('"')


def part_meta(msg):
    ct_raw = msg.get("Content-Type")
    declared = msg.get_content_type() if ct_raw else ""
    cte = str(msg.get("Content-Transfer-Encoding", "") or "")
    fname = header_filename(msg)
    disp = str(msg.get("Content-Disposition", "") or "").lower()
    role = "attachment" if ("attachment" in disp or fname) else "body"
    try:
        charset = msg.get_content_charset()
    except Exception:
        charset = None
    return declared, cte, fname, role, charset


def decode_body(text, a, b, cte):
    """Decode text[a:b] according to its declared CTE, auto-detecting when the
    declaration is missing or wrong. Returns (data, encoding, cut, omap, notes)."""
    body = text[a:b]
    cte = (cte or "").strip().lower().strip('"')
    notes = []
    enc = "raw"
    if cte == "base64":
        enc = "base64" if looks_base64(body, strict=False) else "raw"
        if enc == "raw":
            notes.append("declared base64 but content is raw")
    elif cte == "quoted-printable":
        enc = "quoted-printable"
    elif cte in ("", "7bit", "8bit", "binary"):
        if looks_base64(body, strict=True) and undeclared_b64_ok(text, a, b):
            enc = "base64"
            notes.append("undeclared base64 detected" if not cte else "declared %s but content is base64" % cte)
        elif not cte and looks_qp(body):
            enc = "quoted-printable"
            notes.append("undeclared quoted-printable detected")
    else:
        notes.append("unsupported encoding %s, kept raw" % cte)

    omap, cut = None, False
    if enc == "base64":
        data, cut, omap, n2 = b64_decode_region(text, a, b)
        notes += n2
    elif enc == "quoted-printable":
        data = quopri.decodestring(body.encode("latin-1"))
    else:
        data = body.encode("latin-1")
    inner = b64_nested(data)
    if inner is not None:
        data = inner
        notes.append("decoded twice")
    return data, enc, cut, omap, notes


# ---------------------------------------------------------------------------
# S1 standard parser
# ---------------------------------------------------------------------------
def header_start(text):
    """Offset of the first header line, skipping mbox/junk lines before the headers."""
    for m in LINE_EOL_RE.finditer(text, 0, min(len(text), 4096)):
        if HEADER_LIKE_RE.match(m.group()):
            return m.start()
    return 0


def raw_payload(part):
    """The part's body exactly as it appears in the file, in the same latin-1 view
    as ctx.text. get_payload(decode=False) is not used: for 8bit parts it converts
    non-ASCII bytes with the part's charset, so the text can no longer be found in
    the file (e.g. b'\xe2\x80\x9c' becomes a curly quote)."""
    payload = getattr(part, "_payload", None)
    if not isinstance(payload, str):
        return None
    try:
        return payload.encode("ascii", "surrogateescape").decode("latin-1")
    except UnicodeEncodeError:
        return payload


def s1_standard(ctx):
    skip = header_start(ctx.text)
    try:
        msg = message_from_bytes(ctx.raw[skip:], policy=compat32)
    except Exception as exc:
        log.debug("%s: email parser failed: %s", ctx.name, exc)
        return
    search_from = skip
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = raw_payload(part)
        if payload is None or not payload.strip():
            continue
        declared, cte, fname, role, charset = part_meta(part)
        stripped = payload.lstrip()
        probe = stripped.splitlines()[0][:76] if stripped else ""
        pos = ctx.text.find(probe, search_from) if probe else -1
        if pos < 0:
            continue                     # cannot locate it; S2-S6 will cover it
        start = max(pos - (len(payload) - len(stripped)), 0)
        end = min(start + len(payload), ctx.size)
        if ctx.text[start:end] != payload:
            start = ctx.text.find(payload, search_from)
            if start < 0:
                continue                 # payload is not a contiguous slice; leave it to S2-S6
            end = start + len(payload)
        search_from = max(pos + len(probe), end)
        if ctx.overlaps(start, end):
            continue
        data, enc, cut, omap, notes = decode_body(ctx.text, start, end, cte)
        c = Candidate(data, "standard_parser", enc, declared, fname, (start, end),
                      omap, cut, role, charset, notes)
        c.whole_body = part is msg or declared.startswith("multipart/")
        # a multipart message the parser could not split: its "body" is the whole
        # message, so it must not block or outrank what S2-S6 find inside it
        c.multipart_fallback = declared.startswith("multipart/")
        ctx.add(c)


# ---------------------------------------------------------------------------
# S2 boundary recovery
# ---------------------------------------------------------------------------
def find_boundaries(ctx):
    declared = set()
    for m in BOUNDARY_PARAM_RE.finditer(ctx.text):
        tok = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if tok:
            declared.add(tok.lower())
    hits = []
    counts = Counter()
    for m in DASH_LINE_RE.finditer(ctx.text):
        tok = m.group(1)
        if len(tok) < 6 or not tok.strip("-=_*#~"):
            continue
        hits.append(m)
        counts[tok.lower()] += 1
    lines = []
    tokens = set()
    for m in hits:
        tok = m.group(1)
        key = tok.lower()
        ok = key in declared or counts[key] >= 2
        if not ok:
            after = ctx.text[m.end():m.end() + 400].lstrip("\r\n")
            ok = HEADER_LIKE_RE.match(after) is not None
        if not ok:
            continue
        tokens.add(tok)
        le = m.end()
        if ctx.text[le:le + 2] == "\r\n":
            le += 2
        elif ctx.text[le:le + 1] in ("\n", "\r"):
            le += 1
        lines.append((m.start(), le, tok, bool(m.group(2))))
    ctx.boundaries = tokens
    ctx.boundary_lines = lines


BLANK_BEFORE_RE = re.compile(r"(?:\r\n|\n|\r)[ \t]*(?:\r\n|\n|\r)$")
PART_HEADER_RE = re.compile(
    r"^(?:content-type|content-transfer-encoding|content-disposition)[ \t]*:", re.I | re.M)


def segments_from_boundaries(ctx):
    """(seg_start, seg_end, unclosed) for each part between boundary lines."""
    lines = ctx.boundary_lines
    out = []
    for i, (_ls, le, tok, closing) in enumerate(lines):
        if closing:
            continue
        unclosed = i + 1 >= len(lines)
        seg_end = ctx.size if unclosed else lines[i + 1][0]
        out.append((le, seg_end, unclosed))
    return out


def segments_from_part_headers(ctx):
    """No boundary lines at all: a part starts wherever a Content-* header block
    follows a blank line after the message headers, and runs to the next one."""
    top = BLANK_LINE_RE.search(ctx.text, header_start(ctx.text))
    if not top:
        return []
    starts = []
    for m in PART_HEADER_RE.finditer(ctx.text, top.end()):
        p = m.start()
        before = ctx.text[max(top.end(), p - 8):p]
        # a blank line right before the headers, in any mix of \r\n, \n and \r
        if p == top.end() or BLANK_BEFORE_RE.search(before):
            if starts and ctx.text[starts[-1]:p].count("\n") < 1:
                continue
            hb = BLANK_LINE_RE.search(ctx.text, p)
            if hb and all(HEADER_LIKE_RE.match(l) or l[:1] in " \t"
                          for l in ctx.text[p:hb.start()].splitlines() if l.strip()):
                starts.append(p)
    out = []
    for i, p in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else ctx.size
        out.append((p, end, False))
    return out


def s2_boundaries(ctx):
    segs = segments_from_boundaries(ctx)
    by_headers = False
    if not segs:
        segs = segments_from_part_headers(ctx)
        by_headers = True
    for seg_start, seg_end, unclosed in segs:
        if seg_end <= seg_start:
            continue
        # the line break before the next boundary belongs to the boundary;
        # without boundaries, blank lines between parts are trimmed instead
        if by_headers:
            while seg_end > seg_start and ctx.text[seg_end - 1] in "\r\n":
                seg_end -= 1
        elif not unclosed:
            if ctx.text[seg_end - 2:seg_end] == "\r\n":
                seg_end -= 2
            elif ctx.text[seg_end - 1:seg_end] in ("\n", "\r"):
                seg_end -= 1
        seg = ctx.text[seg_start:seg_end]
        declared, cte, fname, role, charset = "", "", "", "body", None
        body_start = seg_start
        if HEADER_LIKE_RE.match(seg):
            hb = BLANK_LINE_RE.search(seg)
            if not hb:
                continue                     # cut inside the part headers
            hmsg = message_from_string(seg[:hb.start()] + "\n\n", policy=compat32)
            declared, cte, fname, role, charset = part_meta(hmsg)
            body_start = seg_start + hb.end()
        if declared.startswith("multipart/"):
            continue
        if body_start >= seg_end or not ctx.text[body_start:seg_end].strip():
            continue
        if ctx.overlaps(body_start, seg_end):
            continue
        data, enc, cut, omap, notes = decode_body(ctx.text, body_start, seg_end, cte)
        if unclosed:
            notes.append("segment not closed")
        if by_headers:
            notes.append("segmented by part headers (no boundaries)")
        ctx.add(Candidate(data, "boundary_recovery", enc, declared, fname,
                          (body_start, seg_end), omap, cut or unclosed, role, charset, notes))


# ---------------------------------------------------------------------------
# S4 helpers (also used by S3 and the residue check)
# ---------------------------------------------------------------------------
def find_b64_blocks(text, a, b, min_chars=B64_MIN_BLOCK_CHARS):
    """Line-structured base64 blocks in text[a:b] as (start, end) ranges.
    One junk line inside a block is tolerated."""
    blocks = []
    cur = None                                # [start, end, nchars, line_len, junk]

    def close():
        if cur is not None and cur[2] >= min_chars:
            blocks.append((cur[0], cur[1]))

    for m in LINE_EOL_RE.finditer(text, a, b):
        s = m.group().strip()
        is_b64 = bool(s) and B64_LINE_RE.fullmatch(s) is not None
        if is_b64:
            if cur is None:
                if len(s) < B64_MIN_LINE_CHARS:
                    continue
                cur = [m.start(), m.end(), len(s), len(s), False]
                if s.endswith("="):
                    close()
                    cur = None
                continue
            cur[1] = m.end()
            cur[2] += len(s)
            cur[4] = False
            if s.endswith("=") or len(s) < cur[3]:
                close()
                cur = None
            continue
        if cur is not None:
            if s and not cur[4] and len(s) <= 200:
                cur[4] = True                 # tolerate one junk line
                continue
            close()
            cur = None
    close()
    return blocks


def find_qp_paragraphs(text, a, b):
    out, pos = [], a
    for m in list(BLANK_LINE_RE.finditer(text, a, b)) + [None]:
        end = m.start() if m else b
        para = text[pos:end]
        if para.strip() and not HEADER_LIKE_RE.match(para.lstrip()) and looks_qp(para):
            out.append((pos, end))
        pos = m.end() if m else b
    return out


def carve_at(ctx, start, t):
    """Carve raw bytes starting at `start` up to the next boundary, the next file of
    the same kind (pdf), or end of file. Returns (data, cut)."""
    limit = ctx.next_boundary_after(start) or ctx.size
    for s, _e in ctx.claims:
        if start < s < limit:
            limit = s
    if t == "pdf":
        nxt = ctx.raw.find(b"%PDF-", start + 5, limit)
        if nxt > 0:
            limit = nxt
    data = ctx.raw[start:limit]
    cut = limit >= ctx.size
    if t not in END_FINDERS:
        data = data.rstrip(b"\r\n")
    return data, cut


# ---------------------------------------------------------------------------
# S3 header-index pairing
# ---------------------------------------------------------------------------
NAME_PARAM_RE = re.compile(r"""(?:file)?name\*?\s*=\s*(?:"([^"]*)"|([^;\s]+))""", re.I)


def s3_header_index(ctx):
    m = BLANK_LINE_RE.search(ctx.text)
    if not m:
        return
    head = re.sub(r"\r?\n[ \t]+", " ", ctx.text[:m.start()])
    entries = []
    for line in head.splitlines():
        mm = re.match(r"\s*content-type\s*:\s*(.*)", line, re.I)
        if mm:
            val = mm.group(1)
            mime = val.split(";")[0].strip().lower()
            if not mime or mime.startswith("multipart/"):
                continue
            nm = NAME_PARAM_RE.search(val)
            entries.append([mime, (nm.group(1) or nm.group(2)) if nm else ""])
        elif entries and re.match(r"\s*content-disposition\s*:", line, re.I) and not entries[-1][1]:
            nm = NAME_PARAM_RE.search(line)
            if nm:
                entries[-1][1] = nm.group(1) or nm.group(2)
    if len(entries) < 2:
        return
    ctx.has_structure = True
    wanted = [e for e in entries if not e[0].startswith("text/")]
    blocks = []
    for ga, gb in ctx.gaps(m.end()):
        blocks += [("b64", s, e) for s, e in find_b64_blocks(ctx.text, ga, gb)]
        for sm in RAW_SIG_RE.finditer(ctx.raw, ga, gb):
            start = sm.start() - (257 if sm.group().startswith(b"ustar") else
                                  4 if sm.group().startswith(b"ftyp") else 0)
            if start >= ga:
                blocks.append(("raw", start, None))
    blocks.sort(key=lambda x: x[1])
    used_until = -1
    for (mime, fname), (kind, s, e) in zip(wanted, blocks):
        if s < used_until or ctx.claimed_at(s):
            continue
        if kind == "b64":
            data, cut, omap, notes = b64_decode_region(ctx.text, s, e)
            c = Candidate(data, "header_index", "base64", mime, fname, (s, e), omap, cut,
                          "attachment", None, notes)
        else:
            t = sniff(ctx.raw[s:s + 512], strict=True)
            if not t:
                continue
            data, cut = carve_at(ctx, s, t)
            e = s + len(data)
            c = Candidate(data, "header_index", "raw", mime, fname, (s, e), None, cut)
        ctx.add(c)
        used_until = e


# ---------------------------------------------------------------------------
# S4 encoded block scan
# ---------------------------------------------------------------------------
def glued_line_start(ctx, s, e, floor):
    """If the line before block [s, e) ends with exactly one more base64 line glued
    onto other text (e.g. 'Content-Type: image/pngiVBORw0...'), return its start."""
    first = LINE_RE.match(ctx.text, s)
    if not first:
        return s
    width = len(first.group().strip())
    prev_end = s
    while prev_end > floor and ctx.text[prev_end - 1] in "\r\n":
        prev_end -= 1
    if prev_end <= floor:
        return s
    ls = max(ctx.text.rfind("\n", floor, prev_end), ctx.text.rfind("\r", floor, prev_end)) + 1
    prev = ctx.text[ls:prev_end]
    if len(prev) > width and not B64_LINE_RE.fullmatch(prev.strip()) \
            and B64_RUN_RE.fullmatch(prev[-width:]):
        return prev_end - width
    return s


def s4_encoded_blocks(ctx):
    for ga, gb in ctx.gaps():
        for s, e in find_b64_blocks(ctx.text, ga, gb):
            if ctx.overlaps(s, e):
                continue
            if glued_line_start(ctx, s, e, ga) != s:
                continue                 # starts mid-line: S5 finds the true start
            data, cut, omap, notes = b64_decode_region(ctx.text, s, e)
            ctx.add(Candidate(data, "encoded_block_scan", "base64", src=(s, e), omap=omap,
                              cut=cut or e >= ctx.size, notes=notes))
    for ga, gb in ctx.gaps():
        for s, e in find_qp_paragraphs(ctx.text, ga, gb):
            if ctx.overlaps(s, e):
                continue
            data = quopri.decodestring(ctx.raw[s:e])
            ctx.add(Candidate(data, "encoded_block_scan", "quoted-printable", src=(s, e),
                              role="body", cut=e >= ctx.size))


# ---------------------------------------------------------------------------
# S5 base64 anchor scan
# ---------------------------------------------------------------------------
def _head_type(compact, off):
    head = compact[off:off + 400]
    head = head[:len(head) // 4 * 4]
    if len(head) < 16:
        return ""
    try:
        hb = base64.b64decode(head)
    except (binascii.Error, ValueError):
        return ""
    return sniff(hb, strict=True)


GLUE_MIMES = sorted(set(k.split("/")[0] + "/" + k.split("/")[1] for k in MIME_TO_TYPE
                        if re.fullmatch(r"[a-z]+/[a-z0-9]+", k)), key=len, reverse=True)


def s5_anchor_scan(ctx):
    for ga, gb in ctx.gaps():
        for sm in B64_STRETCH_RE.finditer(ctx.text, ga, gb):
            a, b = sm.start(), sm.end()
            omap = OffsetMap()
            chunks = []
            for rm in B64_RUN_RE.finditer(ctx.text, a, b):
                omap.add(rm.start(), rm.end() - rm.start())
                chunks.append(rm.group())
            compact = "".join(chunks)
            off_base = 0
            low = ctx.text[a:a + 120].lower()
            mime_prefix = max((m for m in GLUE_MIMES if low.startswith(m)), key=len, default="")
            if mime_prefix:
                raw_start = a + len(mime_prefix)
                data, cut, sub, notes = b64_decode_region(ctx.text, raw_start, b, strict_lengths=False)
                if data and not sniff(data, strict=True) and text_of(data) is not None:
                    c = ctx.add(Candidate(data, "base64_anchor_scan", "base64", src=(raw_start, b),
                                          omap=sub, cut=cut or b >= ctx.size,
                                          notes=notes + ["base64 glued after '%s'" % mime_prefix]))
                    off_base = len(mime_prefix) + -(-len(c.data) // 3) * 4
            while off_base < len(compact) - 16:
                hit = -1
                for off in range(off_base, min(off_base + B64_MAX_ANCHOR_OFFSET, len(compact) - 16)):
                    if _head_type(compact, off):
                        hit = off
                        break
                if hit < 0:
                    break
                raw_start = omap.raw(hit)
                if ctx.claimed_at(raw_start):
                    off_base = hit + 4
                    continue
                data, cut, _m, notes = b64_decode_region(ctx.text, raw_start, b, strict_lengths=False)
                sub = OffsetMap()
                for rm in B64_RUN_RE.finditer(ctx.text, raw_start, b):
                    sub.add(rm.start(), rm.end() - rm.start())
                if hit > 0:
                    notes.append("file starts %d chars into a base64 stretch" % hit)
                c = ctx.add(Candidate(data, "base64_anchor_scan", "base64", src=(raw_start, b),
                                      omap=sub, cut=cut or b >= ctx.size, notes=notes))
                used = -(-(len(c.data) + c.lead) // 3) * 4 if c.data else 4
                off_base = hit + max(used, 4)


# ---------------------------------------------------------------------------
# S6 raw signature carve
# ---------------------------------------------------------------------------
def s6_raw_carve(ctx):
    last_end = 0
    for sm in RAW_SIG_RE.finditer(ctx.raw):
        g = sm.group()
        start = sm.start() - (257 if g.startswith(b"ustar") else 4 if g.startswith(b"ftyp") else 0)
        if start < 0 or start < last_end or ctx.claimed_at(start):
            continue
        head = ctx.raw[start:start + 8192]
        t = sniff(head, strict=True)
        if not t or not carve_plausible("zip" if t in ZIP_SUBTYPES else t, head):
            continue
        data, cut = carve_at(ctx, start, t)
        c = ctx.add(Candidate(data, "raw_signature_carve", "raw", src=(start, start + len(data)),
                              cut=cut))
        last_end = start + c.lead + max(len(c.data), 1)


# ---------------------------------------------------------------------------
# Post-processing: supersede, filter, de-duplicate, name
# ---------------------------------------------------------------------------
def type_selected(t, types):
    if types is None:
        return True
    if t in types:
        return True
    return "other" in types and (t == "other" or t not in BUILTIN_TYPES)


def finalize(ctx, min_size, types):
    cands = ctx.candidates
    known = [c for c in cands if not c.status and c.detected_type != "other" and c.claimed]
    for c in cands:
        if c.status or not c.src or not is_fallback(c):
            continue
        for k in known:
            if k is not c and c.src[0] < k.claimed[1] and k.claimed[0] < c.src[1]:
                c.status = "duplicate"
                c.reason = "same source bytes recovered as %s by %s" % (k.detected_type, k.method)
                c.kept_ref = k
                break

    for c in cands:
        if c.status:
            continue
        if len(c.data) < min_size:
            c.status, c.reason = "below_min_size", "%d bytes < %d" % (len(c.data), min_size)
        elif not type_selected(c.detected_type, types):
            c.status, c.reason = "type_filtered", "%s not in --types" % c.detected_type

    pool = [c for c in cands if not c.status]
    pool.sort(key=lambda c: (c.partial, -len(c.data) if c.partial else 0,
                             METHOD_RANK[c.method], c.position))
    kept, by_hash = [], {}
    for c in pool:
        k = by_hash.get(c.sha256)
        if k is None and c.partial:
            for kk in kept:
                if kk.detected_type == c.detected_type and kk.data.startswith(c.data):
                    k = kk
                    break
        if k is not None:
            c.status, c.reason, c.kept_ref = "duplicate", "same bytes already recovered", k
            continue
        kept.append(c)
        by_hash[c.sha256] = c

    kept.sort(key=lambda c: (c.position, METHOD_RANK[c.method]))
    for i, c in enumerate(kept, 1):
        ext = TYPE_EXT.get(c.detected_type, "." + c.detected_type)
        c.out_name = "part_%03d%s%s" % (i, "_partial" if c.partial else "", ext)
        c.status = "partial" if c.partial else "recovered"
        if c.partial and not c.reason:
            c.reason = next((n for n in c.notes if n.startswith("end of") or n == "segment not closed"),
                            "stream cut short")
    for c in cands:
        if c.status == "duplicate" and c.kept_ref is not None and c.kept_ref.out_name:
            c.notes.append("duplicate of %s" % c.kept_ref.out_name)
    return kept


# ---------------------------------------------------------------------------
# Per-email processing
# ---------------------------------------------------------------------------
def atomic_write(folder, name, data):
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, os.path.join(folder, name))
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def copy_eml(src, folder):
    os.makedirs(folder, exist_ok=True)
    dst = os.path.join(folder, os.path.basename(src))
    tmp = dst + ".tmp_copy"
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)


def recover(raw, name, min_size, types):
    """Run all strategies on one email. Returns (ctx, kept)."""
    ctx = Ctx(raw, name)
    find_boundaries(ctx)
    ctx.has_structure = bool(ctx.boundary_lines) or bool(
        find_b64_blocks(ctx.text, 0, ctx.size, RESIDUE_B64_RUN_CHARS))
    s1_standard(ctx)
    s2_boundaries(ctx)
    s3_header_index(ctx)
    s4_encoded_blocks(ctx)
    s5_anchor_scan(ctx)
    s6_raw_carve(ctx)
    kept = finalize(ctx, min_size, types)
    return ctx, kept


def row(name, dest, c=None, status="", reason=""):
    if c is None:
        return {"eml_name": name, "eml_destination": dest, "extraction_method": "",
                "declared_type": "", "declared_filename": "", "detected_type": "",
                "encoding": "", "sha256": "", "status": status, "reason": reason, "remark": ""}
    return {"eml_name": name, "eml_destination": dest, "extraction_method": c.method,
            "declared_type": c.declared_type, "declared_filename": c.declared_filename,
            "detected_type": c.detected_type, "encoding": c.encoding, "sha256": c.sha256,
            "status": c.status, "reason": c.reason,
            "remark": "; ".join(dict.fromkeys(([c.out_name] if c.out_name else []) + c.notes))}


def process_email(path, out_root, min_size, types):
    name = os.path.basename(path)
    with open(path, "rb") as fh:
        raw = fh.read()
    ctx, kept = recover(raw, name, min_size, types)
    if kept:
        dest = EXTRACTED_DIR
        folder = os.path.join(out_root, EXTRACTED_DIR, os.path.splitext(name)[0])
        os.makedirs(folder, exist_ok=True)
        for c in kept:
            atomic_write(folder, c.out_name, c.data)
        copy_eml(path, folder)
    else:
        dest = NOT_EXTRACTED_DIR
        copy_eml(path, os.path.join(out_root, NOT_EXTRACTED_DIR))
    if not ctx.candidates:
        return [row(name, dest, status="no_content_found",
                    reason="no MIME part, encoded block or file signature found")], kept
    order = sorted(ctx.candidates, key=lambda c: (c.position, METHOD_RANK[c.method]))
    return [row(name, dest, c) for c in order], kept


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_types(value):
    if not value:
        return None
    types = set(canonical_type(t) for t in value.split(",") if t.strip())
    unknown = sorted(t for t in types if t not in BUILTIN_TYPES)
    if unknown:
        log.warning("--types: %s not in the built-in table; matched only via libmagic",
                    ", ".join(unknown))
    return types


def open_report(out_root):
    path = os.path.join(out_root, REPORT_NAME)
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    fh = open(path, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
    if new:
        writer.writeheader()
        fh.flush()
    return fh, writer


def main(argv=None):
    ap = argparse.ArgumentParser(description="Recover MIME content from malformed .eml files.")
    ap.add_argument("--input", help="folder containing .eml files")
    ap.add_argument("--output", help="folder for Extracted/, Not Extracted/ and the report")
    ap.add_argument("--min-size", "--min_size", dest="min_size", type=int, default=MIN_SIZE,
                    help="reject recovered parts smaller than this many bytes (default %d)" % MIN_SIZE)
    ap.add_argument("--types", default="",
                    help="comma-separated types to keep, e.g. pdf,jpg,docx,other (default: all)")
    ap.add_argument("--no-magic", action="store_true", help="never use libmagic")
    ap.add_argument("--check-magic", action="store_true",
                    help="only test whether libmagic works for this Python, then exit")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.check_magic:
        state = init_magic(False, verbose=True)
        log.info("libmagic: %s", state)
        return 0 if state.startswith("on") else 1
    if not args.input or not args.output:
        ap.error("--input and --output are required")
    if not os.path.isdir(args.input):
        log.error("input folder not found: %s", args.input)
        return 2
    if args.min_size < 0:
        log.error("--min-size must be >= 0")
        return 2
    types = parse_types(args.types)
    magic_state = init_magic(args.no_magic)

    try:
        for sub in (EXTRACTED_DIR, NOT_EXTRACTED_DIR):
            os.makedirs(os.path.join(args.output, sub), exist_ok=True)
        fh, writer = open_report(args.output)
    except OSError as exc:
        log.error("cannot write to output folder %s: %s", args.output, exc)
        return 1

    files = sorted(f for f in os.listdir(args.input)
                   if f.lower().endswith(".eml") and os.path.isfile(os.path.join(args.input, f)))
    stats = Counter()
    with fh:
        for f in files:
            path = os.path.join(args.input, f)
            try:
                rows, kept = process_email(path, args.output, args.min_size, types)
                stats["extracted" if kept else "not_extracted"] += 1
            except Exception as exc:                 # one bad email never stops the run
                log.exception("failed on %s", f)
                try:
                    copy_eml(path, os.path.join(args.output, NOT_EXTRACTED_DIR))
                except OSError:
                    pass
                rows = [row(f, NOT_EXTRACTED_DIR, status="processing_error",
                            reason="%s: %s" % (type(exc).__name__, exc))]
                stats["errors"] += 1
            for r in rows:
                stats[r["status"]] += 1
            writer.writerows(rows)
            fh.flush()

    log.info("done: %d emails (%d extracted, %d not extracted, %d errors); "
             "parts recovered %d, partial %d, duplicate %d, rejected %d; magic %s",
             len(files), stats["extracted"], stats["not_extracted"], stats["errors"],
             stats["recovered"], stats["partial"], stats["duplicate"],
             stats["below_min_size"] + stats["type_filtered"] + stats["mime_residue"]
             + stats["decode_failed"], magic_state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
