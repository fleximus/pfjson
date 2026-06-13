# pfjson

A CLI tool to convert OpenBSD Packet Filter configuration files (`pf.conf`) to JSON and vice versa.

## Features

- Bidirectional conversion between pf.conf and JSON formats
- Preserves comments and formatting
- Checksum verification using SHA256 and SHA512 for data integrity
- File metadata tracking including original filename and file size
- File overwrite protection requiring explicit force flag ("-f")
- Stdin/stdout support using "-" as filename
- Syntax checking (`-c`) and dry-run (`-n`) modes
- Line-by-line structure that preserves source order and formatting
- Parsing of common pf.conf elements:
  - Macros and variables
  - Tables with IP/hostname entries
  - Filter rules (pass/block), including TCP `flags`
  - Match rules (incl. `nat-to`/`rdr-to` redirection)
  - NAT and RDR rules
  - Scrub rules
  - Antispoof rules
  - Options and settings (`set ...`)
  - `include` and `load anchor` directives
  - Comments (standalone and inline)

Unrecognized lines are preserved verbatim (as `unknown`) so conversion stays
lossless, but `-c` reports them since pfjson cannot validate syntax it does not
understand.

## Installation

```bash
# Compile from source
v .
```

## Quick Start

```bash
# Convert your pf.conf to JSON (backup)
pfjson -e /etc/pf.conf backup.json

# Restore from JSON backup
pfjson -d backup.json restored.conf

# Validate your pf.conf syntax
pfjson -c -e /etc/pf.conf
```

## Usage

### Help

```bash
$ pfjson -h
pfjson v0.9.0
Author: Felix Ehlers
License: MIT License
-----------------------------------------------
Usage: pfjson [options] [ARGS]

Description: A CLI tool to convert OpenBSD Packet Filter configuration files (`pf.conf`) to JSON and vice versa.

Options:
  -e, --encode              Encode pf.conf to JSON (default false)
  -d, --decode              Decode JSON to pf.conf (default false)
  -c, --check               Syntax check only (default false)
  -n, --dry-run             Dry run mode (default false)
  -v, --verify              Strict checksum verification (fail on mismatch) (default false)
  -f, --force               Force overwrite existing output files (default false)
  -j, --json                Machine-parsable JSON output (default false)
  -h, --help                display this help and exit
  --version                 output version information and exit
```

Running `pfjson` with no arguments prints the version banner followed by this
usage. Version, author, and license are also shown by `pfjson --version`.

### Encoding (pf.conf → JSON)

Convert a pf.conf file to JSON format:

```bash
# Output to stdout
$ pfjson -e pf.conf

# Output to file
$ pfjson -e pf.conf output.json

# Read from stdin (use "-" as filename)
$ cat pf.conf | pfjson -e -
$ echo 'ext_if = "em0"' | pfjson -e -

# Syntax check only (no output)
$ pfjson -c -e pf.conf

# Dry run (show what would be output)
$ pfjson -n -e pf.conf
```

Example pf.conf:
```bash
# External interface
ext_if = "em0"

# Web server
web_server = "192.168.1.10"

# Blocked IPs table
table <blocklist> { 10.0.0.1, 10.0.0.2 }

# Set options
set block-policy drop
set skip on lo0

# NAT rule
nat on $ext_if from 192.168.1.0/24 to any -> ($ext_if)

# Filter rules
block in all
pass out all
pass in on $ext_if proto tcp from any to $web_server port 80
```

Generated JSON output (abbreviated):
```json
{
  "metadata": {
    "filename": "pf.conf",
    "timestamp": "2026-06-13 20:49:38",
    "filesize": 285,
    "checksums": {
      "sha256": "2b407e08...",
      "sha512": "09a240ae..."
    }
  },
  "lines": [
    { "line_num": 1, "line_type": "comment", "raw_line": "# External interface" },
    { "line_num": 2, "line_type": "macro", "name": "ext_if", "value": "em0" },
    { "line_num": 3, "line_type": "table", "name": "blocklist",
      "values": ["10.0.0.1", "10.0.0.2"],
      "raw_line": "table <blocklist> { 10.0.0.1, 10.0.0.2 }" },
    { "line_num": 4, "line_type": "option", "option_name": "skip", "option_value": "on lo0",
      "raw_line": "set skip on lo0" },
    { "line_num": 5, "line_type": "rule", "action": "block", "direction": "in",
      "raw_line": "block in all" }
  ]
}
```

The output is a flat, ordered list of lines. Each entry carries a `line_type`
and only the fields relevant to it (empty fields are omitted), plus a `raw_line`
when the original formatting needs to be preserved exactly. The `metadata`
block records the original filename, a timestamp, the file size, and SHA256/SHA512
checksums used to verify a faithful round-trip on decode.

### Decoding (JSON → pf.conf)

Convert a JSON file back to pf.conf format:

```bash
# Output to stdout
$ pfjson -d config.json

# Output to file
$ pfjson -d config.json restored.conf

# Read from stdin (use "-" as filename)
$ cat config.json | pfjson -d -
$ pfjson -e pf.conf | pfjson -d -

# Force overwrite existing file
$ pfjson -d -f config.json existing.conf

# Strict verification mode (fail if checksums don't match)
$ pfjson -d -v config.json

# Dry run (show what would be generated)
$ pfjson -n -d config.json
```

### File Safety

By default, pfjson will not overwrite existing files:

```bash
$ pfjson -e pf.conf existing.json
Error encoding: Output file already exists: existing.json. Use -f to force overwrite.

$ pfjson -e -f pf.conf existing.json
Encoded to: existing.json
```

### Checksum Verification

The tool automatically verifies data integrity during conversion:

```bash
$ pfjson -d config.json
✓ Checksum verification passed - output matches original (from pf.conf)

$ pfjson -d -v tampered.json
Error decoding: Checksum verification failed - output does not match original metadata (from pf.conf)
```

Without `-v`, a mismatch is reported as a warning and conversion still proceeds;
with `-v` it is a hard error and pfjson exits non-zero.

### Error Handling

Common error scenarios and their solutions:

```bash
# Unrecognized / invalid lines in pf.conf (-c reports each with its line number)
$ pfjson -e -c broken.conf
Syntax check: FAILED (1 error(s))
  line 5: unrecognized or unsupported syntax: this is not valid pf

# File doesn't exist
$ pfjson -e missing.conf
Error encoding: Input file does not exist: missing.conf

# Attempting to overwrite existing file
$ pfjson -e pf.conf existing.json
Error encoding: Output file already exists: existing.json. Use -f to force overwrite.

# Round-trip mismatch during restore (strict mode)
$ pfjson -d -v corrupted.json
Error decoding: Checksum verification failed - output does not match original metadata
```

> **Note:** `-c` validates the subset of pf.conf that pfjson recognizes. Lines it
> cannot classify (e.g. `anchor`, `queue`/`altq`)
> are reported as "unrecognized or unsupported syntax" — the checker cannot
> distinguish unsupported from invalid. For full grammar validation, use `pfctl -nf`.

### Machine-Parsable JSON Output

The `-j` flag provides structured JSON responses for automation and scripting:

```bash
# Successful operation
$ pfjson -e -j pf.conf backup.json
{"success":true,"message":"File encoded successfully","data":{"output_file":"backup.json","input_file":"pf.conf"},"error":""}

# Syntax check (passing)
$ pfjson -e -c -j pf.conf
{"success":true,"message":"Syntax check passed","data":{},"error":""}

# Syntax check (failing) - exits non-zero, details in the "error" field
$ pfjson -e -c -j broken.conf
{"success":false,"message":"Syntax check failed: 1 error(s)","data":{},"error":"line 5: unrecognized or unsupported syntax"}

# Checksum verification with details
$ pfjson -d -j backup.json
{"success":true,"message":"Checksum verification passed (from pf.conf)","data":{"sha256":"abc123...","sha512":"def456...","size":"2048"},"error":""}

# Error handling
$ pfjson -e -j missing.conf
{"success":false,"message":"Encoding failed","data":{},"error":"Input file does not exist: missing.conf"}

# Integration with jq for processing
$ pfjson -e -j pf.conf backup.json | jq -r '.data.output_file'
backup.json

$ pfjson -c -e -j pf.conf | jq '.success'
true
```

JSON Response Structure:
- `success`: Boolean indicating operation success
- `message`: Status message
- `data`: Structured data (file paths, checksums)
- `error`: Error details when `success=false`

## License

See `LICENSE`

