module main

import os

fn test_basic_encoding() {
	// Create a simple test file
	test_content := '# Test file\next_if = "eth0"\npass in all'
	os.write_file('test_input.conf', test_content) or { panic(err) }
	
	// Test encoding
	result := os.execute('./pfjson -e test_input.conf test_output.json')
	assert result.exit_code == 0
	assert os.exists('test_output.json')
	
	// Clean up
	os.rm('test_input.conf') or {}
	os.rm('test_output.json') or {}
}

fn test_basic_decoding() {
	// Create a simple test JSON
	json_content := '{
		"metadata": {
			"sha256": "test",
			"sha512": "test", 
			"filesize": 100
		},
		"raw_text": "# Test\\next_if = \\"eth0\\"\\npass in all",
		"config": {
			"macros": [{"name": "ext_if", "value": "eth0"}],
			"tables": [],
			"options": [],
			"scrub_rules": [],
			"nat_rules": [],
			"rules": [{"action": "pass", "direction": "in", "interface": "all", "protocol": "", "source": "", "destination": "", "port": "", "options": [], "comment": ""}],
			"comments": []
		}
	}'
	
	os.write_file('test_input.json', json_content) or { panic(err) }
	
	// Test decoding
	result := os.execute('./pfjson -d test_input.json test_output.conf')
	assert result.exit_code == 0
	assert os.exists('test_output.conf')
	
	// Clean up
	os.rm('test_input.json') or {}
	os.rm('test_output.conf') or {}
}

fn test_syntax_check() {
	// Create a simple test file
	test_content := 'ext_if = "eth0"'
	os.write_file('test_syntax.conf', test_content) or { panic(err) }
	
	// Test syntax check
	result := os.execute('./pfjson -c -e test_syntax.conf')
	assert result.exit_code == 0
	assert result.output.contains('Syntax check: OK')
	
	// Clean up
	os.rm('test_syntax.conf') or {}
}

fn test_dry_run() {
	// Create a simple test file
	test_content := 'ext_if = "eth0"'
	os.write_file('test_dry.conf', test_content) or { panic(err) }
	
	// Test dry run
	result := os.execute('./pfjson -n -e test_dry.conf')
	assert result.exit_code == 0
	assert result.output.contains('Dry run - would output:')
	
	// Clean up
	os.rm('test_dry.conf') or {}
}

fn test_file_metadata() {
	// Create a test file
	test_content := 'ext_if = "eth0"'
	os.write_file('test_meta.conf', test_content) or { panic(err) }
	
	// Test encoding to get metadata
	result := os.execute('./pfjson -e test_meta.conf')
	assert result.exit_code == 0
	
	// Check that output contains metadata fields
	assert result.output.contains('sha256')
	assert result.output.contains('sha512') 
	assert result.output.contains('filesize')
	
	// Clean up
	os.rm('test_meta.conf') or {}
}

fn test_checksum_verification() {
	// Clean up any existing test files
	os.rm('test_checksum.conf') or {}
	os.rm('test_checksum.json') or {}

	// Create a test file and encode it
	test_content := '# Test\next_if = "eth0"\npass in all'
	os.write_file('test_checksum.conf', test_content) or { panic(err) }
	
	// Encode to JSON
	result := os.execute('./pfjson -e test_checksum.conf test_checksum.json')
	assert result.exit_code == 0
	assert os.exists('test_checksum.json')
	
	// Decode back and verify checksums match (should pass)
	result2 := os.execute('./pfjson -d test_checksum.json')
	assert result2.exit_code == 0
	assert result2.output.contains('✓ Checksum verification passed')
	
	// Test strict verification mode (should also pass)
	result3 := os.execute('./pfjson -d -v test_checksum.json')
	assert result3.exit_code == 0
	assert result3.output.contains('✓ Checksum verification passed')
	
	// Clean up
	os.rm('test_checksum.conf') or {}
	os.rm('test_checksum.json') or {}
}

fn test_checksum_verification_failure() {
	// Create a JSON file with invalid checksums to test failure detection
	invalid_json := '{
		"metadata": {
			"filename": "test_file.conf",
			"sha256": "invalid_checksum",
			"sha512": "invalid_checksum",
			"filesize": 999
		},
		"raw_text": "ext_if = \\"eth0\\"",
		"config": {
			"macros": [],
			"tables": [],
			"options": [],
			"scrub_rules": [],
			"nat_rules": [],
			"rules": [],
			"comments": []
		}
	}'
	
	os.write_file('test_invalid.json', invalid_json) or { panic(err) }
	
	// Test with warning mode (should succeed but warn)
	result := os.execute('./pfjson -d test_invalid.json')
	assert result.exit_code == 0
	assert result.output.contains('Warning: Generated output checksums do not match')
	assert result.output.contains('(from test_file.conf)')
	
	// Test with strict verification (should fail)
	result2 := os.execute('./pfjson -d -v test_invalid.json')
	assert result2.exit_code == 1
	assert result2.output.contains('Checksum verification failed')
	assert result2.output.contains('(from test_file.conf)')
	
	// Clean up
	os.rm('test_invalid.json') or {}
}

fn test_filename_storage() {
	// Create a test file and encode it
	test_content := 'ext_if = "eth0"'
	os.write_file('test_filename.conf', test_content) or { panic(err) }
	
	// Encode to JSON
	result := os.execute('./pfjson -e test_filename.conf test_filename.json')
	assert result.exit_code == 0
	assert os.exists('test_filename.json')
	
	// Check that filename is stored in JSON
	json_content := os.read_file('test_filename.json') or { panic(err) }
	assert json_content.contains('"filename"')
	assert json_content.contains('"test_filename.conf"')
	
	// Decode and verify filename appears in verification message
	result2 := os.execute('./pfjson -d test_filename.json')
	assert result2.exit_code == 0
	assert result2.output.contains('(from test_filename.conf)')
	
	// Clean up
	os.rm('test_filename.conf') or {}
	os.rm('test_filename.json') or {}
}

fn test_overwrite_protection() {
	// Clean up any existing test files
	os.rm('test_overwrite.conf') or {}
	os.rm('test_overwrite.json') or {}
	os.rm('existing_output.conf') or {}
	os.rm('existing_decode.conf') or {}

	// Create a test file and encode it first
	test_content := 'ext_if = "eth0"'
	os.write_file('test_overwrite.conf', test_content) or { panic(err) }
	
	// Encode to JSON
	result := os.execute('./pfjson -e test_overwrite.conf test_overwrite.json')
	assert result.exit_code == 0
	assert os.exists('test_overwrite.json')
	
	// Create an existing output file to test protection
	os.write_file('existing_output.conf', 'existing content') or { panic(err) }
	
	// Test encode protection (should fail without -f)
	result2 := os.execute('./pfjson -e test_overwrite.conf existing_output.conf')
	assert result2.exit_code == 1
	assert result2.output.contains('Output file already exists')
	
	// Test encode with force flag (should succeed)
	result3 := os.execute('./pfjson -e -f test_overwrite.conf existing_output.conf')
	assert result3.exit_code == 0
	assert result3.output.contains('Encoded to: existing_output.conf')
	
	// Recreate the existing file for decode test
	os.write_file('existing_decode.conf', 'existing decode content') or { panic(err) }
	
	// Test decode protection (should fail without -f)
	result4 := os.execute('./pfjson -d test_overwrite.json existing_decode.conf')
	assert result4.exit_code == 1
	assert result4.output.contains('Output file already exists')
	
	// Test decode with force flag (should succeed)
	result5 := os.execute('./pfjson -d -f test_overwrite.json existing_decode.conf')
	assert result5.exit_code == 0
	assert result5.output.contains('Decoded to: existing_decode.conf')
	
	// Clean up
	os.rm('test_overwrite.conf') or {}
	os.rm('test_overwrite.json') or {}
	os.rm('existing_output.conf') or {}
	os.rm('existing_decode.conf') or {}
}

