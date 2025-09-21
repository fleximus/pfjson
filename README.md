# pfjson

A CLI tool to convert OpenBSD Packet Filter configuration files (`pf.conf`) to JSON and vice versa.

## Features

- Bidirectional conversion between pf.conf and JSON formats
- Preserves comments and formatting
- Checksum verification using SHA256 and SHA512 for data integrity
- File metadata tracking including original filename and file size
- File overwrite protection requiring explicit force flag ("-f")
- Stdin/stdout support using "-" as filename
- Syntax validation and dry-run modes
- Full parsing of all pf.conf elements:
  - Macros and variables
  - Tables with IP/hostname entries
  - Filter rules (pass/block)
  - NAT and RDR rules
  - Scrub rules
  - Options and settings
  - Comments (standalone and inline)

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
-----------------------------------------------
Usage: pfjson [options] [ARGS]

Description: CLI tool to convert pf.conf to JSON and vice versa

Options:
  -e, --encode              Encode pf.conf to JSON
  -d, --decode              Decode JSON to pf.conf
  -c, --check               Syntax check only
  -n, --dry-run             Dry run mode
  -v, --verify              Strict checksum verification (fail on mismatch)
  -f, --force               Force overwrite existing output files
  -j, --json                Machine-parsable JSON output
  -h, --help                display this help and exit
  --version                 output version information and exit
```

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

Generated JSON output:
```json
{
  "metadata": {
    "filename": "pf.conf",
    "sha256": "a1b2c3d4e5f6...",
    "filesize": 285
  },
  "config": {
    "macros": [{"name": "ext_if", "value": "em0"}],
    "tables": [{"name": "blocklist", "entries": ["10.0.0.1", "10.0.0.2"]}],
    "rules": [...],
    "nat_rules": [...]
  }
}
```

The JSON contains structured representations of all pf.conf elements with metadata for integrity verification.

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
Error encoding: Output file "existing.json" already exists. Use -f to force overwrite.

$ pfjson -e -f pf.conf existing.json
Encoded to: existing.json
```

### Checksum Verification

The tool automatically verifies data integrity during conversion:

```bash
$ pfjson -d config.json
Checksum verification passed - output matches original (from pf.conf)

$ pfjson -d -v tampered.json
Error decoding: Checksum verification failed - output does not match original metadata (from pf.conf)
```

### Error Handling

Common error scenarios and their solutions:

```bash
# Invalid syntax in pf.conf
$ pfjson -c -e broken.conf
Error: Syntax error at line 5: unexpected token 'invalid'

# File doesn't exist
$ pfjson -e missing.conf
Error: Input file does not exist: missing.conf

# Attempting to overwrite existing file
$ pfjson -e pf.conf existing.json
Error: Output file "existing.json" already exists. Use -f to force overwrite.

# Corrupted JSON during restore
$ pfjson -d -v corrupted.json
Error: Checksum verification failed - data integrity compromised
```

### Machine-Parsable JSON Output

The `-j` flag provides structured JSON responses for automation and scripting:

```bash
# Successful operation
$ pfjson -e -j pf.conf backup.json
{"success":true,"message":"File encoded successfully","data":{"output_file":"backup.json","input_file":"pf.conf"}}

# Syntax check
$ pfjson -c -e -j pf.conf
{"success":true,"message":"Syntax check passed"}

# Checksum verification with details
$ pfjson -d -j backup.json
{"success":true,"message":"Checksum verification passed (from pf.conf)","data":{"sha256":"abc123...","sha512":"def456...","size":"2048"}}

# Error handling
$ pfjson -e -j nonexistent.conf
{"success":false,"message":"Encoding failed","error":"Input file does not exist: nonexistent.conf"}

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

