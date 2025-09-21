module main

import os

fn test_enhanced_nat_array_parsing() {
	// Test NAT rules with comma-separated array values
	nat_array_tests := [
		// NAT with braced source array
		'nat pass log on \$vpn_if from { \$net_dmz } to { 192.168.178.4 } -> (\$lan_if)',
		// NAT with multiple sources
		'nat on \$ext_if from { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } to any -> (\$ext_if)',
		// RDR with complex arrays
		'rdr on \$ext_if proto tcp from { 172.16.0.65, 172.16.0.66 } to any port { 80, 443 } -> 10.0.0.1',
	]
	
	for i, test_content in nat_array_tests {
		test_file := 'test_nat_array_${i}.conf'
		json_file := 'test_nat_array_${i}.json'
		output_file := 'test_nat_array_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains structured arrays
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":\t"nat"') || json_content.contains('"line_type":\t"rdr"')
		
		// Should have parsed arrays properly
		if test_content.contains('{ \$net_dmz }') {
			assert json_content.contains('"sources":\t["\$net_dmz"]')
		}
		if test_content.contains('{ 192.168.178.4 }') {
			assert json_content.contains('"destinations":\t["192.168.178.4"]')
		}
		if test_content.contains('{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }') {
			assert json_content.contains('"sources":\t["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]')
		}
		if test_content.contains('{ 80, 443 }') {
			assert json_content.contains('"ports":\t["80", "443"]')
		}
		
		// Test round-trip conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for NAT array test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_icmp_type_parsing() {
	// Test ICMP type parsing in rules
	icmp_tests := [
		// IPv4 ICMP type
		'pass in on \$ext_if proto icmp from any to any icmp-type echoreq',
		// IPv6 ICMP type
		'pass in on \$ext_if proto icmp6 from any to any icmp6-type neighbradv',
		// Complex ICMP rule
		'pass in quick on \$ext_if proto icmp from any to \$ext_if icmp-type { echoreq, echorep } keep state',
	]
	
	for i, test_content in icmp_tests {
		test_file := 'test_icmp_${i}.conf'
		json_file := 'test_icmp_${i}.json'
		output_file := 'test_icmp_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains ICMP type fields
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":\t"rule"')
		
		if test_content.contains('icmp-type echoreq') {
			assert json_content.contains('"icmp_type":\t"echoreq"')
		}
		if test_content.contains('icmp6-type neighbradv') {
			assert json_content.contains('"icmp6_type":\t"neighbradv"')
		}
		if test_content.contains('icmp-type { echoreq, echorep }') {
			assert json_content.contains('"icmp_type":\t"{ echoreq, echorep }"')
		}
		
		// Test round-trip conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for ICMP test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_structured_option_parsing() {
	// Test structured parsing for set/option commands
	option_tests := [
		// Skip interface option
		'set skip on lo',
		// Limit option
		'set limit states 100000',
		// Block policy option
		'set block-policy return',
		// Multiple options
		'set skip on lo\nset limit states 50000\nset optimization normal',
	]
	
	for i, test_content in option_tests {
		test_file := 'test_option_${i}.conf'
		json_file := 'test_option_${i}.json'
		output_file := 'test_option_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains structured option data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":\t"option"')
		
		if test_content.contains('set skip on lo') {
			assert json_content.contains('"option_name":\t"skip"')
			assert json_content.contains('"option_value":\t"on lo"')
		}
		if test_content.contains('set limit states 100000') {
			assert json_content.contains('"option_name":\t"limit"')
			assert json_content.contains('"option_value":\t"states 100000"')
		}
		if test_content.contains('set block-policy return') {
			assert json_content.contains('"option_name":\t"block-policy"')
			assert json_content.contains('"option_value":\t"return"')
		}
		
		// Test round-trip conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for option test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}

fn test_structured_antispoof_parsing() {
	// Test structured parsing for antispoof rules
	antispoof_tests := [
		// Basic antispoof
		'antispoof for em0',
		// Antispoof with log
		'antispoof log for em1',
		// Antispoof with multiple options
		'antispoof log quick for em2',
	]
	
	for i, test_content in antispoof_tests {
		test_file := 'test_antispoof_${i}.conf'
		json_file := 'test_antispoof_${i}.json'
		output_file := 'test_antispoof_${i}_output.conf'
		
		// Write test configuration
		os.write_file(test_file, test_content) or { panic(err) }
		
		// Encode to JSON
		encode_result := os.execute('./pfjson -e -f ${test_file} ${json_file}')
		assert encode_result.exit_code == 0
		assert os.exists(json_file)
		
		// Verify JSON contains structured antispoof data
		json_content := os.read_file(json_file) or { panic(err) }
		assert json_content.contains('"line_type":\t"antispoof"')
		
		if test_content.contains('for em0') {
			assert json_content.contains('"interfaces":\t["em0"]')
		}
		if test_content.contains('for em1') {
			assert json_content.contains('"interfaces":\t["em1"]')
		}
		if test_content.contains('for em2') {
			assert json_content.contains('"interfaces":\t["em2"]')
		}
		if test_content.contains('log') {
			assert json_content.contains('"log":\ttrue')
		}
		if test_content.contains('quick') {
			assert json_content.contains('quick')
		}
		
		// Test round-trip conversion
		decode_result := os.execute('./pfjson -d -f ${json_file} ${output_file}')
		assert decode_result.exit_code == 0
		assert os.exists(output_file)
		
		// Verify round-trip fidelity
		original_content := os.read_file(test_file) or { panic(err) }
		output_content := os.read_file(output_file) or { panic(err) }
		assert original_content == output_content, 'Round-trip conversion failed for antispoof test ${i}'
		
		// Clean up
		os.rm(test_file) or {}
		os.rm(json_file) or {}
		os.rm(output_file) or {}
	}
}