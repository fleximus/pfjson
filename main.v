module main

import os
import flag
import json

const app_version = '0.10.0'
const app_name = 'pfjson'
const app_author = 'Felix Ehlers'
const app_license = 'MIT License'

struct Config {
mut:
	encode      bool
	decode      bool
	check       bool
	dry_run     bool
	verify      bool
	force       bool
	json_output bool
	input       string
	output      string
}

struct FileMetadata {
	filename   string
	timestamp  string // when the parsing was done
	filesize   i64
	checksums  Checksums
}

struct Checksums {
	sha256 string
	sha512 string
}

struct PfJsonOutput {
	metadata FileMetadata
	raw_text string @[omitempty] // Keep for compatibility but usually empty
	lines    []PfLine // Primary line-by-line structure
}

struct JsonResponse {
	success bool
	message string
	data    map[string]string @[optional]
	error   string @[optional]
}

struct ConfigElement {
	line_num     int
	element_type string
	content      string
}

fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application(app_name)
	fp.version("v${app_version}\nAuthor: ${app_author}\nLicense: ${app_license}")
	fp.description('A CLI tool to convert OpenBSD Packet Filter configuration files (`pf.conf`) to JSON and vice versa.')

	encode := fp.bool('encode', `e`, false, 'Encode pf.conf to JSON')
	decode := fp.bool('decode', `d`, false, 'Decode JSON to pf.conf')
	check := fp.bool('check', `c`, false, 'Syntax check only')
	dry_run := fp.bool('dry-run', `n`, false, 'Dry run mode')
	verify := fp.bool('verify', `v`, false, 'Strict checksum verification (fail on mismatch)')
	force := fp.bool('force', `f`, false, 'Force overwrite existing output files')
	json_output := fp.bool('json', `j`, false, 'Machine-parsable JSON output')

	additional_args := fp.finalize() or {
		eprintln(err)
		exit(1)
	}

	// No arguments at all - show version banner and usage
	if os.args.len == 1 {
		println(fp.usage())
		exit(0)
	}

	if !encode && !decode {
		eprintln('Error: Must specify either -e (encode) or -d (decode)')
		exit(1)
	}

	if encode && decode {
		eprintln('Error: Cannot specify both -e and -d')
		exit(1)
	}

	// Skip the program name in additional_args
	actual_args := if additional_args.len > 0 && additional_args[0] == os.args[0] {
		additional_args[1..]
	} else {
		additional_args
	}
	
	// Handle argument parsing for input/output
	mut input_file := ''
	mut output_file := ''
	
	if actual_args.len == 0 {
		// No arguments - use stdin for input
		input_file = '-'
	} else if actual_args.len == 1 {
		// A single argument is always the input; output defaults to stdout.
		// Use "-" for stdin. To write stdin to a file, give both explicitly:
		// e.g. `pfjson -e - output.json`.
		input_file = actual_args[0]
	} else {
		// Two or more arguments - first is input, second is output 
		input_file = actual_args[0]
		output_file = actual_args[1]
	}

	mut config := Config{
		encode: encode
		decode: decode
		check: check
		dry_run: dry_run
		verify: verify
		force: force
		json_output: json_output
		input: input_file
		output: output_file
	}

	if config.encode {
		encode_pf_to_json(config) or {
			if config.json_output {
				response := JsonResponse{
					success: false
					message: 'Encoding failed'
					error: err.msg()
				}
				eprintln(json.encode(response))
			} else {
				eprintln('Error encoding: ${err}')
			}
			exit(1)
		}
	} else if config.decode {
		decode_json_to_pf(config) or {
			if config.json_output {
				response := JsonResponse{
					success: false
					message: 'Decoding failed'
					error: err.msg()
				}
				eprintln(json.encode(response))
			} else {
				eprintln('Error decoding: ${err}')
			}
			exit(1)
		}
	}
}
