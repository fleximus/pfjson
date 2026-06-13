module main

import os
fn test_stdin_encoding() {
	// Test encoding from stdin
	result := os.execute('echo \'ext_if = "eth0"\' | ./pfjson -e -')
	assert result.exit_code == 0
	assert result.output.contains('"filename":	"<stdin>"')
	assert result.output.contains('"line_type":	"macro"')
	assert result.output.contains('"sha256"')
	assert result.output.contains('"filesize":	15')
}

fn test_stdin_decoding() {
	// First create valid JSON from a known input
	encode_result := os.execute('echo \'ext_if = "eth0"\' | ./pfjson -e -')
	assert encode_result.exit_code == 0
	
	// Then decode it via stdin
	result := os.execute('echo \'${encode_result.output}\' | ./pfjson -d -')
	assert result.exit_code == 0
	assert result.output.contains('ext_if = "eth0"')
	assert result.output.contains('✓ Checksum verification passed')
	assert result.output.contains('(from <stdin>)')
}

fn test_stdin_round_trip() {
	// Test complete round-trip through stdin
	test_content := 'ext_if = "eth0"'
	result := os.execute('echo \'${test_content}\' | ./pfjson -e - | ./pfjson -d -')
	assert result.exit_code == 0
	assert result.output.contains('ext_if = "eth0"')
	assert result.output.contains('✓ Checksum verification passed - output matches original (from <stdin>)')
}

// ===== COMPREHENSIVE CONVERSION TESTS =====

fn test_macros_conversion() {
	// Test various macro configurations
	macro_tests := [
		// Simple macro
		'ext_if = "eth0"',
		// Multiple macros
		'ext_if = "eth0"\nint_if = "eth1"\nnet_internal = "192.168.1.0/24"',
		// Macros with special characters
		'hosts_allowed = "{ 192.168.1.10, 192.168.1.20, 192.168.1.30 }"',
		// Macro with complex value
		'voip_phones = "{ 172.16.0.65, 172.16.0.66, 172.16.0.67 }"',
	]
	
	for i, test_content in macro_tests {
		// Test conf -> json conversion
		test_file := 'test_macro_${i}.conf'
		json_file := 'test_macro_${i}.json'
		output_file := 'test_macro_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains expected macro data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":	"macro"')
		if test_content.contains('ext_if') {
			assert json_content.contains('"name":	"ext_if"')
			assert json_content.contains('"value":	"eth0"')
		}
		
		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for macro test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_tables_conversion() {
	// Test various table configurations
	table_tests := [
		// Basic table with values
		'table <blocklist> { 97.107.130.116, 192.168.1.100 }',
		// Persistent table
		'table <dynamic_hosts> persist',
		// Table with complex entries
		'table <voip_phones> { 172.16.0.65, 172.16.0.66, 172.16.0.67 }',
		// Multiple tables
		'table <allowed> { 192.168.1.10, 192.168.1.20 }\ntable <blocked> persist',
	]
	
	for i, test_content in table_tests {
		// Test conf -> json conversion
		test_file := 'test_table_${i}.conf'
		json_file := 'test_table_${i}.json'
		output_file := 'test_table_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains expected table data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":	"table"')
		if test_content.contains('blocklist') {
			assert json_content.contains('"name":	"blocklist"')
			assert json_content.contains('"values"')
		}
		if test_content.contains('persist') {
			assert json_content.contains('"persist":	true')
		}
		
		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for table test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_nat_rules_conversion() {
	// Test various NAT rule configurations
	nat_tests := [
		// Basic NAT rule
		'nat on \$ext_if from 192.168.1.0/24 to any -> (\$ext_if)',
		// NAT with pass action
		'nat pass on \$vpn_if from { \$net_dmz } to { 192.168.178.4 } -> (\$lan_if)',
		// NAT with log
		'nat log on \$ext_if from \$internal_net to any -> (\$ext_if)',
		// NAT with pass and log
		'nat pass log on \$vpn_if from { \$net_dmz } to { 192.168.178.4 } -> (\$lan_if)',
		// No NAT rule
		'no nat on \$ext_if from 10.0.0.0/8 to any',
	]
	
	for i, test_content in nat_tests {
		// Test conf -> json conversion
		test_file := 'test_nat_${i}.conf'
		json_file := 'test_nat_${i}.json'
		output_file := 'test_nat_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains expected NAT data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":	"nat"')
		if test_content.contains('pass') {
			assert json_content.contains('"rule_type":	"pass"')
		}
		if test_content.contains('log') {
			// Log can be either a boolean field (for NAT) or in options array (for rules)
			assert json_content.contains('"log":	true') || json_content.contains('"log"')
		}
		if test_content.contains('no nat') {
			assert json_content.contains('"rule_type":	"no nat"')
		}
		
		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for NAT test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_rdr_rules_conversion() {
	// Test various RDR rule configurations
	rdr_tests := [
		// Basic RDR rule
		'rdr on \$ext_if proto tcp from any to \$ext_if port 80 -> 192.168.1.10 port 8080',
		// RDR with pass action
		'rdr pass on \$ext_if proto tcp from any to \$ext_if port 22 -> 192.168.1.5 port 22',
		// RDR with complex port specification
		'rdr on \$ext_if proto tcp from <voip_phones> to \$lan_mail01 port { ldap, ldaps } -> \$prv_zion',
		// RDR with complex source
		'rdr on \$ext_if proto tcp from { 172.16.0.65 } to any port 443 -> 10.0.0.1',
	]
	
	for i, test_content in rdr_tests {
		// Test conf -> json conversion
		test_file := 'test_rdr_${i}.conf'
		json_file := 'test_rdr_${i}.json'
		output_file := 'test_rdr_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains expected RDR data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":	"rdr"')
		if test_content.contains('rdr pass') {
			assert json_content.contains('"rule_type":	"pass"')
		}
		if test_content.contains('proto tcp') {
			assert json_content.contains('"protocols":	["tcp"]')
		}
		if test_content.contains('{ ldap, ldaps }') {
			assert json_content.contains('"ports":	["ldap", "ldaps"]')
		}
		
		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for RDR test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_regular_rules_conversion() {
	// Test various regular rule configurations
	rule_tests := [
		// Basic pass rule
		'pass in all',
		// Block rule with quick
		'block out quick on \$ext_if from <badguys> to any',
		// Complex rule with multiple options
		'pass in quick on \$int_if proto tcp from \$internal_net to any port { 80, 443 } keep state',
		// Rule with log
		'pass in log on \$ext_if proto tcp from any to \$ext_if port 22 keep state',
		// Rule with label and tag
		'pass out on \$ext_if from \$internal_net to any keep state label "outbound" tag "allowed"',
		// Rule with dup-to
		'pass in on \$int_if dup-to (\$monitor_if 192.168.100.1) from any to any',
	]
	
	for i, test_content in rule_tests {
		// Test conf -> json conversion
		test_file := 'test_rule_${i}.conf'
		json_file := 'test_rule_${i}.json'
		output_file := 'test_rule_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains expected rule data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":	"rule"')
		if test_content.contains('pass') {
			assert json_content.contains('"action":	"pass"')
		}
		if test_content.contains('block') {
			assert json_content.contains('"action":	"block"')
		}
		if test_content.contains('quick') {
			assert json_content.contains('"quick":	true')
		}
		if test_content.contains('log') {
			// Log can be either a boolean field (for NAT) or in options array (for rules)
			assert json_content.contains('"log":	true') || json_content.contains('"log"')
		}
		
		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for rule test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_scrub_rules_conversion() {
	// Test various scrub rule configurations
	scrub_tests := [
		// Basic scrub
		'scrub in all',
		// Scrub on an interface
		'scrub on \$ext_if all',
		// Scrub with direction, interface and option
		'scrub in on \$ext_if all random-id',
		// Scrub with multi-token options
		'scrub out all max-mss 1440 no-df',
	]

	for i, test_content in scrub_tests {
		test_file := 'test_scrub_${i}.conf'
		json_file := 'test_scrub_${i}.json'
		output_file := 'test_scrub_${i}_output.conf'

		os.write_file(test_file, test_content) or { panic(err) }

		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)

		// Verify JSON contains expected scrub data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":	"scrub"')
		if test_content.contains('scrub in') {
			assert json_content.contains('"direction":	"in"')
		}
		if test_content.contains('on \$ext_if') {
			assert json_content.contains('"interfaces":	["\$ext_if"]')
		}
		assert json_content.contains('"options"')

		// A valid scrub line must pass the syntax check
		check_result := os.execute('./pfjson -e -c ${test_file}')
		assert check_result.exit_code == 0, 'Syntax check failed for scrub test ${i}'

		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)

		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for scrub test ${i}'

		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_comments_conversion() {
	// Test various comment configurations
	comment_tests := [
		// Standalone comment
		'# This is a standalone comment',
		// Multiple comments
		'# Configuration file for pf\n# Updated: 2025-08-01\n# Author: Admin',
		// Mixed content with comments
		'# Network interfaces\next_if = "eth0"\n# Internal network\nint_if = "eth1"',
		// Comment with special characters
		'# ======= FIREWALL RULES =======\n# Block all by default\nblock all',
		// Inline comment
		'pass in all # Allow all inbound traffic',
	]
	
	for i, test_content in comment_tests {
		// Test conf -> json conversion
		test_file := 'test_comment_${i}.conf'
		json_file := 'test_comment_${i}.json'
		output_file := 'test_comment_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains expected comment data
		json_content := os.read_file(json_file) or { panic(err) }
		
		// For inline comments, the line_type will be "rule" not "comment"
		if test_content.contains('pass in all #') {
			assert json_content.contains('"line_type":	"rule"')
			assert json_content.contains('"comment":	"Allow all inbound traffic"')
		} else {
			// For standalone comments
			assert json_content.contains('"line_type":	"comment"')
		}
		
		if test_content.contains('standalone comment') {
			assert json_content.contains('standalone comment')
		}
		
		// Test json -> conf conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for comment test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_round_trip_fidelity() {
	// Test complex mixed configurations for round-trip fidelity
	complex_configs := [
		// Comprehensive configuration
		'# Main configuration
ext_if = "eth0"
int_if = "eth1"
vpn_if = "tun0"

# Tables
table <allowed_hosts> { 192.168.1.10, 192.168.1.20 }
table <blocked_ips> persist

# NAT rules
nat on \$ext_if from 192.168.1.0/24 to any -> (\$ext_if)
nat pass log on \$vpn_if from { \$net_dmz } to { 192.168.178.4 } -> (\$lan_if)

# RDR rules
rdr on \$ext_if proto tcp from any to \$ext_if port 80 -> 192.168.1.10 port 8080
rdr pass on \$ext_if proto tcp from <voip_phones> to \$lan_mail01 port { ldap, ldaps } -> \$prv_zion

# Filter rules
block all
pass out all keep state
pass in on \$int_if from \$internal_net to any keep state
pass in quick on \$ext_if proto tcp from any to \$ext_if port { 22, 80, 443 } keep state',

		// Configuration with comments and mixed content
		'# Configuration file
ext_if = "eth0"
int_if = "eth1"
block all
pass in on \$ext_if proto tcp from any to any port 22 keep state',
	]
	
	for i, test_content in complex_configs {
		// Test complete round-trip conversion
		test_file := 'test_complex_${i}.conf'
		json_file := 'test_complex_${i}.json'
		output_file := 'test_complex_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Test json -> conf conversion with checksum verification
		decode_result := os.execute('./pfjson -d -v -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0, 'Strict verification failed for complex config ${i}'
		assert os.exists(output_file)
		assert decode_result.output.contains('✓ Checksum verification passed')
		
		// Verify content matches exactly
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip fidelity failed for complex config ${i}'
		
		// Test direct round-trip via pipeline
		pipeline_result := os.execute('./pfjson -e ${test_file} | ./pfjson -d -')
		assert pipeline_result.exit_code == 0
		assert pipeline_result.output.contains('✓ Checksum verification passed')
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

// ===== PARSING ENHANCEMENT TESTS =====

