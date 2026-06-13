module main

import json
import crypto.sha256
import crypto.sha512

// report_check_result prints the outcome of a syntax check and exits with a
// non-zero status if any errors were found.
fn report_check_result(errors []ValidationError, json_output bool) {
	if errors.len == 0 {
		if json_output {
			response := JsonResponse{
				success: true
				message: 'Syntax check passed'
			}
			println(json.encode(response))
		} else {
			println('Syntax check: OK')
		}
		return
	}

	if json_output {
		mut details := []string{}
		for e in errors {
			details << 'line ${e.line_num}: ${e.message}'
		}
		response := JsonResponse{
			success: false
			message: 'Syntax check failed: ${errors.len} error(s)'
			error: details.join('; ')
		}
		eprintln(json.encode(response))
	} else {
		eprintln('Syntax check: FAILED (${errors.len} error(s))')
		for e in errors {
			if e.content != '' {
				eprintln('  line ${e.line_num}: ${e.message}: ${e.content}')
			} else {
				eprintln('  line ${e.line_num}: ${e.message}')
			}
		}
	}
	exit(1)
}

fn encode_pf_to_json(config Config) ! {
	content := read_input_content(config.input)!
	
	if config.check {
		check_lines := parse_pf_conf_lines(content)!
		errors := validate_pf_lines(check_lines)
		report_check_result(errors, config.json_output)
		return
	}

	metadata := if config.input == '-' {
		generate_stdin_metadata(content)
	} else {
		generate_file_metadata(config.input)!
	}

	// Use line-by-line parsing as primary method
	parsed_lines := parse_pf_conf_lines(content)!

	pf_json := PfJsonOutput{
		metadata: metadata
		raw_text: '' // Usually empty since we have line-by-line structure
		lines: parsed_lines
	}

	json_output := json.encode_pretty(pf_json)

	if config.dry_run {
		println('Dry run - would output:')
		println(json_output)
		return
	}

	if config.output != '' {
		check_output_file_safety(config.output, config.force)!
		write_file_with_permissions(config.output, json_output)!
		if config.json_output {
			response := JsonResponse{
				success: true
				message: 'File encoded successfully'
				data: {
					'output_file': config.output
					'input_file': if config.input == '-' { '<stdin>' } else { config.input }
				}
			}
			println(json.encode(response))
		} else {
			println('Encoded to: ${config.output}')
		}
	} else {
		println(json_output)
	}
}

fn decode_json_to_pf(config Config) ! {
	json_content := read_input_content(config.input)!
	pf_json := json.decode(PfJsonOutput, json_content)!

	if config.check {
		errors := validate_pf_lines(pf_json.lines)
		report_check_result(errors, config.json_output)
		return
	}

	// Use line-by-line structure for perfect fidelity, fallback to raw_text
	pf_output := if pf_json.lines.len > 0 {
		generate_pf_conf_from_lines(pf_json.lines)!
	} else if pf_json.raw_text != '' {
		pf_json.raw_text
	} else {
		return error('No valid pf.conf data found in JSON (neither lines nor raw_text)')
	}
	
	// Calculate checksums of generated output
	generated_sha256 := sha256.hexhash(pf_output)
	generated_sha512 := sha512.hexhash(pf_output)
	generated_size := pf_output.len
	
	// Compare with stored metadata
	checksum_match := generated_sha256 == pf_json.metadata.checksums.sha256 && 
	                 generated_sha512 == pf_json.metadata.checksums.sha512 &&
	                 generated_size == pf_json.metadata.filesize
	
	if !checksum_match {
		filename_info := if pf_json.metadata.filename != '' { ' (from ${pf_json.metadata.filename})' } else { '' }
		
		if config.json_output {
			response := JsonResponse{
				success: false
				message: 'Checksum verification failed${filename_info}'
				data: {
					'original_sha256': pf_json.metadata.checksums.sha256
					'generated_sha256': generated_sha256
					'original_sha512': pf_json.metadata.checksums.sha512
					'generated_sha512': generated_sha512
					'original_size': pf_json.metadata.filesize.str()
					'generated_size': generated_size.str()
				}
				error: if config.verify { 'Strict verification mode - conversion not 100% faithful' } else { 'Round-trip conversion is not 100% faithful' }
			}
			if config.verify {
				eprintln(json.encode(response))
				return error('Checksum verification failed - output does not match original metadata${filename_info}')
			} else {
				eprintln(json.encode(response))
			}
		} else {
			eprintln('Warning: Generated output checksums do not match original metadata${filename_info}')
			eprintln('SHA256 - Original:  ${pf_json.metadata.checksums.sha256}')
			eprintln('SHA256 - Generated: ${generated_sha256}')
			eprintln('SHA512 - Original:  ${pf_json.metadata.checksums.sha512}')
			eprintln('SHA512 - Generated: ${generated_sha512}')
			eprintln('Size - Original:  ${pf_json.metadata.filesize} bytes')
			eprintln('Size - Generated: ${generated_size} bytes')
			
			if !config.dry_run {
				eprintln('Note: This indicates the round-trip conversion is not 100% faithful')
			}
			
			if config.verify {
				return error('Checksum verification failed - output does not match original metadata${filename_info}')
			}
		}
	} else {
		filename_info := if pf_json.metadata.filename != '' { ' (from ${pf_json.metadata.filename})' } else { '' }
		
		if config.json_output {
			response := JsonResponse{
				success: true
				message: 'Checksum verification passed${filename_info}'
				data: {
					'sha256': generated_sha256
					'sha512': generated_sha512
					'size': generated_size.str()
				}
			}
			eprintln(json.encode(response))
		} else {
			eprintln('✓ Checksum verification passed - output matches original${filename_info}')
		}
	}

	if config.dry_run {
		println('Dry run - would output:')
		println(pf_output)
		return
	}

	if config.output != '' {
		check_output_file_safety(config.output, config.force)!
		write_file_with_permissions(config.output, pf_output)!
		if config.json_output {
			response := JsonResponse{
				success: true
				message: 'File decoded successfully'
				data: {
					'output_file': config.output
					'input_file': if config.input == '-' { '<stdin>' } else { config.input }
				}
			}
			println(json.encode(response))
		} else {
			println('Decoded to: ${config.output}')
		}
	} else {
		println(pf_output)
	}
}