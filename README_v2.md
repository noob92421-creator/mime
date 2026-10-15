# EML MIME recovery

`eml_recover.py` recovers attachments and bodies from `.eml` files that a normal mail
parser rejects: undecoded or wrongly declared encodings, missing or broken boundaries,
Content-Types listed at the top instead of per part, base64 glued onto header lines,
already-decoded binary dumps, and streams cut off mid-file.

Python 3.8+. `python-magic` (libmagic) is optional; everything else is standard library.

## Run

```
python3 eml_recover.py --input /path/Input/ --output /path/Output/ \
    [--min-size 1024] [--types pdf,jpg,png,docx,zip,other] [--no-magic] [-v]
```

| Option | Meaning |
| --- | --- |
| `--input` | Folder of `.eml` files (not recursive) |
| `--output` | Gets `Extracted/`, `Not Extracted/`, `recovery_report.csv` |
| `--min-size` | Reject parts smaller than this many decoded bytes. Default `MIN_SIZE = 1024` at the top of the script. `--min_size` also works |
| `--types` | Keep only these detected types. `jpg`/`jpeg` are aliases; `other` = anything unrecognised. Default: all |
| `--no-magic` | Never use libmagic; built-in signatures only |

Output:

```
Output/
├── Extracted/<eml name>/   original .eml + part_001.pdf, part_002_partial.docx, ...
├── Not Extracted/          emails where nothing survived (the CSV says why)
└── recovery_report.csv     one row per candidate part, appended on every run
```

Cron: folders and the CSV are created only if missing, the CSV is only appended to (header
written once), rows are flushed after each email, and files are written atomically. The
original `.eml` is copied, not moved; the input folder is left to your shell wrapper.

```
*/30 * * * * /usr/bin/python3 /opt/eml/eml_recover.py --input /data/Input --output /data/Output >> /var/log/eml_recover.log 2>&1
```

## libmagic

Optional. Without it the built-in signature table still detects every type listed below;
libmagic only names bytes the table doesn't recognise. Any of the three Python bindings
works: `python-magic` (pip), `file-magic` / Debian's `python3-magic` (apt), or `filemagic`.

Check it with the same Python that cron will use:

```
/usr/bin/python3 eml_recover.py --check-magic
```

It prints `libmagic: on (python-magic)` (exit 0), or the cause and the fix (exit 1):

| Cause printed | Fix |
| --- | --- |
| `No module named 'magic'` | The binding is installed for a different Python. Run `<that python> -m pip install python-magic`, and use the same absolute python path in the crontab |
| `failed to find libmagic` | System library missing: `apt install libmagic1` / `dnf install file-libs` / `apk add libmagic` |
| `could not find any valid magic files` | Database missing: `apt install libmagic-mgc`, or set `MAGIC=/path/to/magic.mgc` |
| `not a libmagic binding` | An unrelated package called `magic` is installed: `pip uninstall magic libmagic`, then `pip install python-magic` |

Every run's summary line also ends with `magic on (...)` or `magic off (unavailable: ...)`.

## How it works

Six strategies run on every email, strict to forgiving. Later ones skip bytes that earlier
ones already recovered, so nothing is extracted twice.

| # | Strategy (`extraction_method`) | Finds |
| --- | --- | --- |
| S1 | `standard_parser` | Well-formed parts, via Python's email parser (junk before the headers is skipped) |
| S2 | `boundary_recovery` | Parts between declared or inferred boundaries; with no boundaries, parts split at each `Content-*` header block |
| S3 | `header_index` | Content-Types listed at the top, paired in order with the bodies below |
| S4 | `encoded_block_scan` | Base64 / quoted-printable blocks with no usable headers (one junk line inside a block is tolerated) |
| S5 | `base64_anchor_scan` | Base64 glued onto other text, e.g. `Content-Type: image/pngiVBORw0...` |
| S6 | `raw_signature_carve` | Already-decoded binary, carved by magic bytes |

Each part is then:

1. **Typed by signature.** The bytes win over the declared Content-Type; a mismatch is noted in `remark`. Exceptions: docx/xlsx/pptx/odt (ZIP) and doc/xls/ppt/msg (OLE) trust the declared subtype when the container matches, otherwise the internal entry/stream names decide. Text has no signature, so JSON must parse, HTML needs tags, and the rest is `txt`.
2. **Checked for completeness.** Formats with an end marker or length field (pdf, png, jpg, gif, zip family, ole family, rar, 7z, tar, gz, mp4/mov, wav/webp/avi, bmp, rtf) are trimmed to their real end; if the end is missing the part is saved as `part_NNN_partial.<ext>`.
3. **Residue-checked if it is text.** Text that is really leaked email structure (MIME headers, boundary lines, a swallowed base64 run) is rejected as `mime_residue`. This is what fixes the "whole eml saved as a txt file" problem, so `txt` can go back into `--types`.
4. **Filtered and de-duplicated.** `--min-size`, then `--types`, then SHA-256 within the email. A complete copy always beats a partial one.

Report statuses: `recovered`, `partial` (written); `duplicate`, `below_min_size`,
`type_filtered`, `mime_residue`, `decode_failed`, `no_content_found`, `processing_error`
(not written).

## Test set

`make_samples.py` generates broken emails with known contents; `evaluate.py` scores an output
folder against them. The same seed always produces the same files.

```
python3 make_samples.py --count 1000 --out samples --truth samples_truth --seed 7
python3 eml_recover.py --input samples --output out --min-size 0
python3 evaluate.py --truth samples_truth --output out
```

Results on the 1,000 samples (seed 7, `--min-size 0`, 2,879 hidden files):

| | Files | Recovered |
| --- | --- | --- |
| Attachments | 1,988 | 98.9% (exact, or the available prefix when the email was cut) |
| Bodies in structured layouts | — | 100% |
| Bodies in header-index / glued / raw-dump layouts | — | not recovered by design: no edges to cut text at |

Every binary type scores 95-100% except exe (87.5%, 16 files). The remaining misses are text attachments with no headers
or edges in raw dumps, two exe and one mp3 run together with the bytes after them (no end
marker to stop at), and files cut off before ~200 base64 characters survived.
