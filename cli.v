module main

import os
import time
import crypto.sha256
import crypto.sha512

// Write file with proper permissions - set mode 600 for new files, leave existing files unchanged
fn write_file_with_permissions(file_path string, content string) ! {
	// Check if file already exists
	file_exists := os.exists(file_path)
	
	// Write the file
	os.write_file(file_path, content)!
	
	// Set permissions only for newly created files
	if !file_exists {
		os.chmod(file_path, 0o600)!  // rw-------
	}
}

fn read_input_content(input_path string) !string {
	if input_path == '-' {
		// Read from stdin
		mut content := ''
		for {
			line := os.get_line()
			if line == '' {
				break
			}
			content += line + '\n'
		}
		// Remove trailing newline if content is not empty
		if content.len > 0 && content.ends_with('\n') {
			content = content[..content.len - 1]
		}
		return content
	} else {
		if !os.exists(input_path) {
			return error('Input file does not exist: ${input_path}')
		}
		return os.read_file(input_path)!
	}
}

fn generate_stdin_metadata(content string) FileMetadata {
	// Generate timestamp in the format "2025-08-01 13:44:12"
	now := time.now()
	timestamp := now.format_ss()
	
	// Calculate file size
	filesize := i64(content.len)
	
	// Generate checksums
	sha256_hash := sha256.sum(content.bytes()).hex()
	sha512_hash := sha512.sum512(content.bytes()).hex()
	
	return FileMetadata{
		filename: '<stdin>'
		timestamp: timestamp
		filesize: filesize
		checksums: Checksums{
			sha256: sha256_hash
			sha512: sha512_hash
		}
	}
}

fn generate_file_metadata(file_path string) !FileMetadata {
	// Get file stats
	stat := os.stat(file_path)!
	
	// Generate timestamp in the format "2025-08-01 13:44:12"
	now := time.now()
	timestamp := now.format_ss()
	
	// Read file content for checksums
	content := os.read_file(file_path)!
	
	// Generate checksums
	sha256_hash := sha256.sum(content.bytes()).hex()
	sha512_hash := sha512.sum512(content.bytes()).hex()
	
	return FileMetadata{
		filename: os.base(file_path)
		timestamp: timestamp
		filesize: stat.size
		checksums: Checksums{
			sha256: sha256_hash
			sha512: sha512_hash
		}
	}
}

fn check_output_file_safety(output_path string, force bool) ! {
	// Skip safety check for stdout
	if output_path == '' || output_path == '-' {
		return
	}
	
	// Check if output file already exists and force is not specified
	if os.exists(output_path) && !force {
		return error('Output file already exists: ${output_path}. Use -f to force overwrite.')
	}
}