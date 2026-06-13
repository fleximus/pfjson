module main

fn parse_pf_conf_lines(content string) ![]PfLine {
	lines := content.split('\n')
	mut pf_lines := []PfLine{}
	
	for i, line in lines {
		line_num := i + 1
		trimmed := line.trim_space()
		
		mut pf_line := PfLine{
			line_num: line_num
		}
		
		if trimmed == '' {
			pf_line.line_type = 'blank'
		} else if trimmed.starts_with('#') {
			pf_line.line_type = 'comment'
			// Store the original line for comments to preserve exact formatting (dashes, spaces, etc.)
			pf_line.raw_line = line
		} else {
			// Try to classify the line type based on content
			if trimmed.contains(' = ') {
				pf_line.line_type = 'macro'
				
				// Smart formatting detection for macros
				eq_pos := line.index(' = ') or { -1 }
				if eq_pos > 0 {
					left_part := line[..eq_pos]
					right_part := line[eq_pos + 3..]
					
					// Check if there's extra formatting (multiple spaces before =)
					name_trimmed := left_part.trim_space()
					value_trimmed := right_part.trim_space().trim('"')
					
					// Detect if formatting has multiple spaces (alignment)
					has_formatting := left_part != name_trimmed || (eq_pos - name_trimmed.len > 1)
					
					pf_line.name = name_trimmed
					pf_line.value = value_trimmed
					
					// Store original content if formatted, otherwise reconstruct
					if has_formatting {
						pf_line.raw_line = line
					}
				}
			} else if trimmed.starts_with('table ') {
				pf_line.line_type = 'table'
				// Parse table components
				table_name, table_values, table_persist := parse_table_line(line)
				pf_line.name = table_name
				pf_line.values = table_values
				pf_line.persist = table_persist
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment if present
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('nat ') || trimmed.starts_with('rdr ') || trimmed.starts_with('no nat ') || trimmed.starts_with('binat ') {
				is_binat := trimmed.starts_with('binat ')
				pf_line.line_type = if trimmed.starts_with('rdr ') {
					'rdr'
				} else if is_binat {
					'binat'
				} else {
					'nat'
				}

				// Parse NAT/binat/RDR components
				if !trimmed.starts_with('rdr ') {
					rule_type, direction, quick, log, iface, inet_family, protocol, source, destination, ports, options, label, tag, tagged, dup_to := parse_nat_rule_line(line)
					// binat has no nat-style rule_type; let the generator fall back to the line_type
					pf_line.rule_type = if is_binat { '' } else { rule_type }
					pf_line.direction = direction
					pf_line.quick = quick
					pf_line.log = log
					pf_line.interfaces = parse_interface_array(iface)
					pf_line.inet_families = parse_inet_family_array(inet_family)
					pf_line.protocols = parse_protocol_array(protocol)
					pf_line.sources = parse_source_array(source)
					pf_line.destinations = parse_destination_array(destination)
					pf_line.ports = parse_port_array(ports)
					pf_line.options = options
					pf_line.label = label
					pf_line.tag = tag
					pf_line.tagged = tagged
					pf_line.dup_to = dup_to
				} else {
					// RDR parsing
					rule_type, direction, quick, iface, inet_family, protocol, source, destination, ports, options, label, tag, tagged, dup_to := parse_rdr_rule_line(line)
					pf_line.rule_type = rule_type
					pf_line.direction = direction
					pf_line.quick = quick
					pf_line.interfaces = parse_interface_array(iface)
					pf_line.inet_families = parse_inet_family_array(inet_family)
					pf_line.protocols = parse_protocol_array(protocol)
					pf_line.sources = parse_source_array(source)
					pf_line.destinations = parse_destination_array(destination)
					pf_line.ports = parse_port_array(ports)
					pf_line.options = options
					pf_line.label = label
					pf_line.tag = tag
					pf_line.tagged = tagged
					pf_line.dup_to = dup_to
				}
				
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment if present
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('set ') {
				pf_line.line_type = 'option'
				// Parse option components
				option_name, option_value := parse_option_line(line)
				pf_line.option_name = option_name
				pf_line.option_value = option_value
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment if present
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('antispoof ') {
				pf_line.line_type = 'antispoof'
				// Parse antispoof components
				antispoof_options, antispoof_interface, has_log := parse_antispoof_line(line)
				pf_line.antispoof = antispoof_options
				pf_line.interfaces = [antispoof_interface]
				pf_line.log = has_log
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment if present
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('scrub ') {
				pf_line.line_type = 'scrub'
				// Parse scrub components
				scrub_direction, scrub_interface, scrub_options := parse_scrub_line(line)
				pf_line.direction = scrub_direction
				if scrub_interface != '' {
					pf_line.interfaces = [scrub_interface]
				}
				pf_line.options = scrub_options
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment if present
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('include ') {
				pf_line.line_type = 'include'
				pf_line.value = parse_include_line(line)
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('load anchor ') {
				pf_line.line_type = 'load'
				load_name, load_path := parse_load_anchor_line(line)
				pf_line.name = load_name
				pf_line.value = load_path
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('nat-anchor ') || trimmed.starts_with('rdr-anchor ')
				|| trimmed.starts_with('binat-anchor ') {
				pf_line.line_type = trimmed.split(' ')[0] // nat-anchor / rdr-anchor / binat-anchor
				anchor_name, anchor_condition, opens_block := parse_anchor_line(line)
				pf_line.name = anchor_name
				pf_line.definition = anchor_condition
				pf_line.block_open = opens_block
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('anchor ') {
				pf_line.line_type = 'anchor'
				anchor_name, anchor_condition, opens_block := parse_anchor_line(line)
				pf_line.name = anchor_name
				pf_line.definition = anchor_condition
				pf_line.block_open = opens_block
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed == '}' {
				pf_line.line_type = 'anchor-close'
				pf_line.raw_line = line  // Preserve original line for exact formatting
			} else if trimmed.starts_with('match ') {
				pf_line.line_type = 'match'
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}

				// Reuse the filter-rule parser for the shared components
				// (action is 'match'; direction/interface/proto/from/to/port/flags).
				action, direction, quick, iface, inet_family, protocol, source, destination, port, options, label, tag, tagged, dup_to, flags, icmp_type, icmp6_type := parse_rule_line(line)
				pf_line.action = action
				pf_line.direction = direction
				pf_line.quick = quick
				pf_line.inet_families = parse_inet_family_array(inet_family)
				pf_line.interfaces = parse_interface_array(iface)
				pf_line.protocols = parse_protocol_array(protocol)
				pf_line.sources = parse_source_array(source)
				pf_line.destinations = parse_destination_array(destination)
				pf_line.ports = parse_port_array(port)
				pf_line.options = options
				pf_line.label = label
				pf_line.tag = tag
				pf_line.tagged = tagged
				pf_line.dup_to = dup_to
				pf_line.flags = flags
				pf_line.icmp_type = icmp_type
				pf_line.icmp6_type = icmp6_type
				route_to, reply_to := parse_rule_routing(line)
				pf_line.route_to = route_to
				pf_line.reply_to = reply_to
				mods := parse_rule_modifiers(line)
				pf_line.user = mods.user
				pf_line.group = mods.group
				pf_line.rtable = mods.rtable
				pf_line.probability = mods.probability
				pf_line.received_on = mods.received_on
				pf_line.divert_to = mods.divert_to
				pf_line.prio = mods.prio

				// Capture the match-specific redirection action, if any.
				redirect_kw, redirect_target := parse_match_redirection(line)
				pf_line.rule_type = redirect_kw
				pf_line.target = redirect_target
			} else if trimmed.starts_with('altq ') {
				pf_line.line_type = 'altq'
				altq_iface, altq_params, altq_queues := parse_altq_line(line)
				if altq_iface != '' {
					pf_line.interfaces = [altq_iface]
				}
				pf_line.definition = altq_params
				pf_line.values = altq_queues
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('queue ') {
				pf_line.line_type = 'queue'
				queue_name, queue_iface, queue_params, queue_subs := parse_queue_line(line)
				pf_line.name = queue_name
				if queue_iface != '' {
					pf_line.interfaces = [queue_iface]
				}
				pf_line.definition = queue_params
				pf_line.values = queue_subs
				pf_line.raw_line = line  // Preserve original line for exact formatting
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			} else if trimmed.starts_with('pass ') || trimmed.starts_with('block ') {
				pf_line.line_type = 'rule'
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment first
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}

				// Parse rule components
				action, direction, quick, iface, inet_family, protocol, source, destination, port, options, label, tag, tagged, dup_to, flags, icmp_type, icmp6_type := parse_rule_line(line)
				pf_line.action = action
				pf_line.direction = direction
				pf_line.quick = quick
				pf_line.inet_families = parse_inet_family_array(inet_family)
				pf_line.interfaces = parse_interface_array(iface)
				pf_line.protocols = parse_protocol_array(protocol)
				pf_line.sources = parse_source_array(source)
				pf_line.destinations = parse_destination_array(destination)
				pf_line.ports = parse_port_array(port)
				pf_line.options = options
				pf_line.label = label
				pf_line.tag = tag
				pf_line.tagged = tagged
				pf_line.dup_to = dup_to
				pf_line.flags = flags
				pf_line.icmp_type = icmp_type
				pf_line.icmp6_type = icmp6_type
				route_to, reply_to := parse_rule_routing(line)
				pf_line.route_to = route_to
				pf_line.reply_to = reply_to
				mods := parse_rule_modifiers(line)
				pf_line.user = mods.user
				pf_line.group = mods.group
				pf_line.rtable = mods.rtable
				pf_line.probability = mods.probability
				pf_line.received_on = mods.received_on
				pf_line.divert_to = mods.divert_to
				pf_line.prio = mods.prio
			} else {
				pf_line.line_type = 'unknown'
				pf_line.raw_line = line  // Preserve original line for exact formatting
				// Extract inline comment if present
				_, inline_comment := extract_inline_comment(line)
				if inline_comment != '' {
					pf_line.comment = inline_comment
				}
			}
		}
		
		pf_lines << pf_line
	}
	
	return pf_lines
}

// Extract inline comment from a line
fn extract_inline_comment(line string) (string, string) {
	// Find the last '#' that's not inside quotes
	mut in_quotes := false
	mut quote_char := `"`
	
	for i := line.len - 1; i >= 0; i-- {
		ch := line[i]
		if ch == `"` || ch == `'` {
			if !in_quotes {
				in_quotes = true
				quote_char = ch
			} else if ch == quote_char {
				in_quotes = false
			}
		} else if ch == `#` && !in_quotes {
			// Found inline comment
			rule_part := line[..i].trim_right(' \t')
			comment_part := line[i + 1..].trim_space()
			return rule_part, comment_part
		}
	}
	
	// No inline comment found
	return line, ''
}

fn parse_rule_line(line string) (string, string, bool, string, string, string, string, string, string, []string, string, string, string, string, string, string, string) {
	// Remove inline comment first
	rule_part, _ := extract_inline_comment(line)
	
	// Split into tokens (simple space-based for now)
	parts := rule_part.trim_space().split(' ')
	if parts.len == 0 {
		return '', '', false, '', '', '', '', '', '', []string{}, '', '', '', '', '', '', ''
	}
	
	mut action := ''
	mut direction := ''
	mut quick := false
	mut iface := ''
	mut inet_family := ''
	mut protocol := ''
	mut source := ''
	mut destination := ''
	mut port := ''
	mut options := []string{}
	mut label := ''
	mut tag := ''
	mut tagged := ''
	mut dup_to := ''
	mut flags := ''
	mut icmp_type := ''
	mut icmp6_type := ''

	mut i := 0
	
	// Parse action (pass/block)
	if i < parts.len {
		action = parts[i]
		i++
	}
	
	// Parse remaining components
	for i < parts.len {
		part := parts[i]
		
		match part {
			'in', 'out' {
				direction = part
				i++
			}
			'quick' {
				quick = true
				i++
			}
			'on' {
				if i + 1 < parts.len {
					i++
					iface = parts[i]
					i++
				} else {
					i++
				}
			}
			'proto' {
				if i + 1 < parts.len {
					i++
					// Handle complex protocols like { tcp, udp }
					if parts[i].starts_with('{') {
						mut proto_parts := []string{}
						for i < parts.len && !parts[i].ends_with('}') {
							proto_parts << parts[i]
							i++
						}
						if i < parts.len {
							proto_parts << parts[i] // include the closing brace
							i++
						}
						protocol = proto_parts.join(' ')
					} else {
						protocol = parts[i]
						i++
					}
				} else {
					i++
				}
			}
			'inet' {
				inet_family = 'inet'
				i++
			}
			'inet6' {
				inet_family = 'inet6'
				i++
			}
			'from' {
				if i + 1 < parts.len {
					i++
					// Handle complex sources like { <vpn-trusted> } or { addr1, addr2 }
					if parts[i].starts_with('{') || parts[i].starts_with('<') {
						mut src_parts := []string{}
						for i < parts.len && !parts[i].ends_with('}') && !parts[i].ends_with('>') {
							src_parts << parts[i]
							i++
						}
						if i < parts.len {
							src_parts << parts[i] // include the closing brace/bracket
							i++
						}
						source = src_parts.join(' ')
					} else {
						source = parts[i]
						i++
					}
				} else {
					i++
				}
			}
			'to' {
				// "to port N" has no destination address; leave 'port' for the
				// port handler rather than consuming it as the destination.
				if i + 1 < parts.len && parts[i + 1] != 'port' {
					i++
					// Handle complex destinations
					if parts[i].starts_with('{') || parts[i].starts_with('<') {
						mut dst_parts := []string{}
						for i < parts.len && !parts[i].ends_with('}') && !parts[i].ends_with('>') {
							dst_parts << parts[i]
							i++
						}
						if i < parts.len {
							dst_parts << parts[i] // include the closing brace/bracket
							i++
						}
						destination = dst_parts.join(' ')
					} else {
						destination = parts[i]
						i++
					}
				} else {
					i++
				}
			}
			'port' {
				if i + 1 < parts.len {
					i++
					// Handle complex ports like { 80, 443 }
					if parts[i].starts_with('{') {
						mut port_parts := []string{}
						for i < parts.len && !parts[i].ends_with('}') {
							port_parts << parts[i]
							i++
						}
						if i < parts.len {
							port_parts << parts[i] // include the closing brace
							i++
						}
						port = port_parts.join(' ')
					} else {
						port = parts[i]
						i++
					}
				} else {
					i++
				}
			}
			'keep' {
				if i + 1 < parts.len && parts[i + 1] == 'state' {
					options << 'keep state'
					i += 2
				} else {
					i++
				}
			}
			'log' {
				options << 'log'
				i++
			}
			'flags' {
				if i + 1 < parts.len {
					i++
					flags = parts[i]
					i++
				} else {
					i++
				}
			}
			'label' {
				if i + 1 < parts.len {
					i++
					label = parts[i]
					i++
				} else {
					i++
				}
			}
			'tag' {
				if i + 1 < parts.len {
					i++
					tag = parts[i]
					i++
				} else {
					i++
				}
			}
			'tagged' {
				if i + 1 < parts.len {
					i++
					tagged = parts[i]
					i++
				} else {
					i++
				}
			}
			'dup-to' {
				if i + 1 < parts.len {
					i++
					// Handle dup-to destinations like ($ext_if 192.168.1.1)
					if parts[i].starts_with('(') {
						mut dup_parts := []string{}
						for i < parts.len && !parts[i].ends_with(')') {
							dup_parts << parts[i]
							i++
						}
						if i < parts.len {
							dup_parts << parts[i] // include the closing paren
							i++
						}
						dup_to = dup_parts.join(' ')
					} else {
						dup_to = parts[i]
						i++
					}
				} else {
					i++
				}
			}
			'icmp-type' {
				if i + 1 < parts.len {
					i++
					// Handle braced expressions like "{ echoreq, echorep }"
					if parts[i].starts_with('{') {
						mut icmp_parts := []string{}
						for i < parts.len {
							icmp_parts << parts[i]
							if parts[i].ends_with('}') {
								break
							}
							i++
						}
						icmp_type = icmp_parts.join(' ')
					} else {
						icmp_type = parts[i]
					}
					i++
				} else {
					i++
				}
			}
			'icmp6-type' {
				if i + 1 < parts.len {
					i++
					// Handle braced expressions like "{ neighbrsol, neighbradv }"
					if parts[i].starts_with('{') {
						mut icmp6_parts := []string{}
						for i < parts.len {
							icmp6_parts << parts[i]
							if parts[i].ends_with('}') {
								break
							}
							i++
						}
						icmp6_type = icmp6_parts.join(' ')
					} else {
						icmp6_type = parts[i]
					}
					i++
				} else {
					i++
				}
			}
			else {
				// Skip unknown tokens
				i++
			}
		}
	}
	
	return action, direction, quick, iface, inet_family, protocol, source, destination, port, options, label, tag, tagged, dup_to, flags, icmp_type, icmp6_type
}

// Parse NAT rule line into components (e.g., "nat pass log on eth0 from { 192.168.1.0/24 } to { any } -> (eth0)")
fn parse_nat_rule_line(line string) (string, string, bool, bool, string, string, string, string, string, string, []string, string, string, string, string) {
	mut action := 'nat'
	mut direction := ''
	mut quick := false
	mut log := false
	mut iface := ''
	mut inet_family := ''
	mut protocol := ''
	mut source := ''
	mut destination := ''
	mut port := ''
	mut options := []string{}
	mut label := ''
	mut tag := ''
	mut tagged := ''
	mut dup_to := ''
	
	// Parse the initial NAT rule type and options
	if line.starts_with('no nat') {
		action = 'no nat'
	} else if line.contains('nat pass log') {
		action = 'pass'
		log = true
	} else if line.contains('nat log') {
		action = 'nat'
		log = true
	} else if line.contains('nat pass') {
		action = 'pass'
	} else {
		action = 'nat'
	}
	
	// Extract components using regex-like parsing
	parts := line.split(' ')
	mut i := 0
	
	for i < parts.len {
		match parts[i] {
			'on' {
				if i + 1 < parts.len {
					i++
					iface = parts[i]
				}
			}
			'from' {
				if i + 1 < parts.len {
					i++
					// Handle complex source specifications like { $net_dmz }
					mut source_parts := []string{}
					if parts[i].starts_with('{') {
						// Collect all parts until we find the closing }
						for i < parts.len && !parts[i].ends_with('}') {
							source_parts << parts[i]
							i++
						}
						if i < parts.len {
							source_parts << parts[i] // Add the closing part
						}
						source_raw := source_parts.join(' ')
						// Keep the braced format for array parsing
						source = source_raw
					} else {
						source = parts[i]
					}
				}
			}
			'to' {
				if i + 1 < parts.len {
					i++
					// Handle complex destination specifications like { 192.168.178.4 }
					mut dest_parts := []string{}
					if parts[i].starts_with('{') {
						// Collect all parts until we find the closing }
						for i < parts.len && !parts[i].ends_with('}') {
							dest_parts << parts[i]
							i++
						}
						if i < parts.len {
							dest_parts << parts[i] // Add the closing part
						}
						dest_raw := dest_parts.join(' ')
						// Keep the braced format for array parsing
						destination = dest_raw
					} else {
						// Handle destination until -> or end
						for i < parts.len && parts[i] != '->' {
							dest_parts << parts[i]
							i++
						}
						if dest_parts.len > 0 {
							destination = dest_parts.join(' ')
						}
						i-- // Adjust for the outer loop increment
					}
				}
			}
			else {}
		}
		i++
	}
	
	return action, direction, quick, log, iface, inet_family, protocol, source, destination, port, options, label, tag, tagged, dup_to
}

// Parse RDR rule line into components (e.g., "rdr on eth0 proto tcp from any to 192.168.1.1 port 80 -> 10.0.0.1 port 8080")
fn parse_rdr_rule_line(line string) (string, string, bool, string, string, string, string, string, string, []string, string, string, string, string) {
	mut action := ''  // Start with empty action
	mut direction := ''
	mut quick := false
	mut iface := ''
	mut inet_family := ''
	mut protocol := ''
	mut source := ''
	mut destination := ''
	mut port := ''
	mut options := []string{}
	mut label := ''
	mut tag := ''
	mut tagged := ''
	mut dup_to := ''
	
	// Detect "pass" action in RDR rules
	if line.contains('rdr pass ') {
		action = 'pass'
	}
	// If no pass is found, action remains empty (will be omitted due to @[omitempty])
	
	// Extract components using regex-like parsing
	parts := line.split(' ')
	mut i := 0
	
	for i < parts.len {
		match parts[i] {
			'on' {
				if i + 1 < parts.len {
					i++
					iface = parts[i]
				}
			}
			'proto' {
				if i + 1 < parts.len {
					i++
					protocol = parts[i]
				}
			}
			'from' {
				if i + 1 < parts.len {
					i++
					// Handle complex source specifications like { 172.16.0.65 }
					mut source_parts := []string{}
					if parts[i].starts_with('{') {
						// Collect all parts until we find the closing }
						for i < parts.len && !parts[i].ends_with('}') {
							source_parts << parts[i]
							i++
						}
						if i < parts.len {
							source_parts << parts[i] // Add the closing part
						}
						source = source_parts.join(' ')
					} else {
						source = parts[i]
					}
				}
			}
			'to' {
				if i + 1 < parts.len {
					i++
					// Handle destination until 'port' or '->'
					mut dest_parts := []string{}
					for i < parts.len && parts[i] != 'port' && parts[i] != '->' {
						dest_parts << parts[i]
						i++
					}
					if dest_parts.len > 0 {
						destination = dest_parts.join(' ')
					}
					i-- // Adjust for the outer loop increment
				}
			}
			'port' {
				if i + 1 < parts.len {
					i++
					// Check if this is source port or destination port
					if parts[i-2] == 'to' || (i > 2 && parts[i-3] == 'to') {
						// Handle complex port specifications like { ldap, ldaps }
						mut port_parts := []string{}
						if parts[i].starts_with('{') {
							// Collect all parts until we find the closing }
							for i < parts.len && !parts[i].ends_with('}') {
								port_parts << parts[i]
								i++
							}
							if i < parts.len {
								port_parts << parts[i] // Add the closing part
							}
							port = port_parts.join(' ')
						} else {
							port = parts[i]
						}
					}
				}
			}
			else {}
		}
		i++
	}
	
	return action, direction, quick, iface, inet_family, protocol, source, destination, port, options, label, tag, tagged, dup_to
}

// Parse protocol string into array (e.g., "{ tcp, udp }" -> ["tcp", "udp"])
fn parse_protocol_array(protocol_str string) []string {
	if protocol_str == '' {
		return []
	}
	
	trimmed := protocol_str.trim_space()
	
	// Handle protocol lists like "{ tcp, udp }"
	if trimmed.starts_with('{') && trimmed.ends_with('}') {
		inner := trimmed[1..trimmed.len-1].trim_space()
		parts := inner.split(',')
		mut protocols := []string{}
		for part in parts {
			cleaned := part.trim_space()
			if cleaned != '' {
				protocols << cleaned
			}
		}
		return protocols
	} else {
		// Single protocol
		return [trimmed]
	}
}

// Parse port string into array (e.g., "{ 80, 443 }" -> ["80", "443"])
fn parse_port_array(port_str string) []string {
	if port_str == '' {
		return []
	}
	
	trimmed := port_str.trim_space()
	
	// Handle port lists like "{ 80, 443 }" or "{ http, https }"
	if trimmed.starts_with('{') && trimmed.ends_with('}') {
		inner := trimmed[1..trimmed.len-1].trim_space()
		parts := inner.split(',')
		mut ports := []string{}
		for part in parts {
			cleaned := part.trim_space()
			if cleaned != '' {
				ports << cleaned
			}
		}
		return ports
	} else {
		// Single port or port range
		return [trimmed]
	}
}

// Parse inet family string into array (handles "inet", "inet6", or empty)
fn parse_inet_family_array(inet_family_str string) []string {
	if inet_family_str == '' {
		return []
	}
	
	trimmed := inet_family_str.trim_space()
	return [trimmed]
}

// Parse source string into array (e.g., "{ addr1, addr2 }" -> ["addr1", "addr2"])
fn parse_source_array(source_str string) []string {
	if source_str == '' {
		return []
	}
	
	trimmed := source_str.trim_space()
	
	// Handle source lists like "{ addr1, addr2 }" or "{ !addr1, !addr2 }"
	if trimmed.starts_with('{') && trimmed.ends_with('}') {
		inner := trimmed[1..trimmed.len-1].trim_space()
		parts := inner.split(',')
		mut sources := []string{}
		for part in parts {
			cleaned := part.trim_space()
			if cleaned != '' {
				sources << cleaned
			}
		}
		return sources
	} else {
		// Single source
		return [trimmed]
	}
}

// Parse interface string into array (e.g., "{ eth0, eth1 }" -> ["eth0", "eth1"])
fn parse_interface_array(interface_str string) []string {
	if interface_str == '' {
		return []
	}
	
	trimmed := interface_str.trim_space()
	
	// Handle interface lists like "{ eth0, eth1 }"
	if trimmed.starts_with('{') && trimmed.ends_with('}') {
		inner := trimmed[1..trimmed.len-1].trim_space()
		parts := inner.split(',')
		mut interfaces := []string{}
		for part in parts {
			cleaned := part.trim_space()
			if cleaned != '' {
				interfaces << cleaned
			}
		}
		return interfaces
	} else {
		// Single interface
		return [trimmed]
	}
}

// Parse destination string into array (e.g., "{ addr1, addr2 }" -> ["addr1", "addr2"])
fn parse_destination_array(destination_str string) []string {
	if destination_str == '' {
		return []
	}
	
	trimmed := destination_str.trim_space()
	
	// Handle destination lists like "{ addr1, addr2 }" or "{ !addr1, !addr2 }"
	if trimmed.starts_with('{') && trimmed.ends_with('}') {
		inner := trimmed[1..trimmed.len-1].trim_space()
		parts := inner.split(',')
		mut destinations := []string{}
		for part in parts {
			cleaned := part.trim_space()
			if cleaned != '' {
				destinations << cleaned
			}
		}
		return destinations
	} else {
		// Single destination
		return [trimmed]
	}
}

// Parse antispoof line into components (e.g., "antispoof log for $ext_if" -> (["quick"], "$ext_if", true))
fn parse_antispoof_line(line string) ([]string, string, bool) {
	trimmed := line.trim_space()
	
	// Remove "antispoof " prefix
	if !trimmed.starts_with('antispoof ') {
		return []string{}, '', false
	}
	
	rest := trimmed[10..].trim_space() // Remove "antispoof "
	parts := rest.split(' ')
	
	mut options := []string{}
	mut iface := ''
	mut has_log := false
	
	// Parse options and interface
	for i, part in parts {
		if part == 'for' && i + 1 < parts.len {
			// Everything before 'for' are options, after 'for' is interface
			for option in parts[..i] {
				if option == 'log' {
					has_log = true
				} else {
					options << option
				}
			}
			iface = parts[i + 1]
			break
		}
	}
	
	// If no 'for' found, assume last part is interface and rest are options
	if iface == '' && parts.len > 0 {
		iface = parts[parts.len - 1]
		if parts.len > 1 {
			for option in parts[..parts.len - 1] {
				if option == 'log' {
					has_log = true
				} else {
					options << option
				}
			}
		}
	}
	
	return options, iface, has_log
}

// Parse scrub line into components
// (e.g., "scrub in on $ext_if all random-id" -> ("in", "$ext_if", ["all", "random-id"]))
fn parse_scrub_line(line string) (string, string, []string) {
	// Remove inline comment first
	rule_part, _ := extract_inline_comment(line)
	trimmed := rule_part.trim_space()

	mut direction := ''
	mut iface := ''
	mut options := []string{}

	if !trimmed.starts_with('scrub') {
		return direction, iface, options
	}

	parts := trimmed.split(' ')
	mut i := 1 // skip 'scrub'
	for i < parts.len {
		part := parts[i]
		match part {
			'' {
				i++
			}
			'in', 'out' {
				direction = part
				i++
			}
			'on' {
				if i + 1 < parts.len {
					i++
					iface = parts[i]
					i++
				} else {
					i++
				}
			}
			else {
				options << part
				i++
			}
		}
	}

	return direction, iface, options
}

// Parse an altq declaration
// (e.g., "altq on $ext_if cbq bandwidth 10Mb queue { std, ssh }"
//  -> ("$ext_if", "cbq bandwidth 10Mb", ["std", "ssh"])).
fn parse_altq_line(line string) (string, string, []string) {
	rule_part, _ := extract_inline_comment(line)
	mut rest := rule_part.trim_space()
	if rest.starts_with('altq') {
		rest = rest[4..].trim_space()
	}

	// Extract the "queue { list }" portion.
	mut queues := []string{}
	if qpos := rest.index('queue') {
		after := rest[qpos + 5..]
		if lb := after.index('{') {
			if rb := after.index('}') {
				for item in after[lb + 1..rb].split(',') {
					cleaned := item.trim_space()
					if cleaned != '' {
						queues << cleaned
					}
				}
			}
		}
		rest = rest[..qpos].trim_space()
	}

	// Extract the interface from "on <if>"; the rest is scheduler/params.
	parts := rest.split(' ')
	mut iface := ''
	mut params := []string{}
	mut i := 0
	for i < parts.len {
		if parts[i] == 'on' && i + 1 < parts.len {
			iface = parts[i + 1]
			i += 2
		} else {
			if parts[i] != '' {
				params << parts[i]
			}
			i++
		}
	}

	return iface, params.join(' '), queues
}

// Parse a queue definition
// (e.g., "queue ssh bandwidth 10% { ssh_login, ssh_bulk }"
//  -> ("ssh", "", "bandwidth 10%", ["ssh_login", "ssh_bulk"])).
fn parse_queue_line(line string) (string, string, string, []string) {
	rule_part, _ := extract_inline_comment(line)
	mut rest := rule_part.trim_space()
	if rest.starts_with('queue') {
		rest = rest[5..].trim_space()
	}

	// Extract the subqueue list "{ ... }".
	mut subqueues := []string{}
	if lb := rest.index('{') {
		if rb := rest.index('}') {
			for item in rest[lb + 1..rb].split(',') {
				cleaned := item.trim_space()
				if cleaned != '' {
					subqueues << cleaned
				}
			}
			rest = (rest[..lb] + rest[rb + 1..]).trim_space()
		}
	}

	// First token is the queue name; pull out "on <if>"; the rest are params.
	parts := rest.split(' ')
	mut name := ''
	mut iface := ''
	mut params := []string{}
	mut i := 0
	if parts.len > 0 {
		name = parts[0]
		i = 1
	}
	for i < parts.len {
		if parts[i] == 'on' && i + 1 < parts.len {
			iface = parts[i + 1]
			i += 2
		} else {
			if parts[i] != '' {
				params << parts[i]
			}
			i++
		}
	}

	return name, iface, params.join(' '), subqueues
}

// Parse an anchor line into its components. Handles plain anchors and the
// nat-anchor / rdr-anchor / binat-anchor variants: inline references
// ('anchor "ftp/*"'), conditional anchors ('anchor "spam" in on egress ...'),
// and block openers ('anchor "x" {'). Returns (name, condition, opens_block).
fn parse_anchor_line(line string) (string, string, bool) {
	rule_part, _ := extract_inline_comment(line)
	trimmed := rule_part.trim_space()
	// Strip the leading anchor keyword (anchor / nat-anchor / rdr-anchor / binat-anchor).
	keyword := trimmed.split(' ')[0]
	if !keyword.ends_with('anchor') {
		return '', '', false
	}

	mut rest := trimmed[keyword.len..].trim_space() // after the anchor keyword
	mut opens_block := false
	if rest.ends_with('{') {
		opens_block = true
		rest = rest[..rest.len - 1].trim_space()
	}

	mut name := ''
	mut condition := ''
	if rest.starts_with('"') {
		// Quoted name; anything after the closing quote is the condition.
		if q := rest[1..].index('"') {
			name = rest[1..1 + q]
			condition = rest[1 + q + 1..].trim_space()
		} else {
			name = rest.trim('"')
		}
	} else if rest != '' {
		// A bareword name, unless the first token is a condition keyword
		// (anonymous anchor with a filter condition).
		parts := rest.split(' ')
		first := parts[0]
		if first in ['in', 'out', 'on', 'inet', 'inet6', 'proto', 'from', 'to'] {
			condition = rest
		} else {
			name = first
			condition = rest[first.len..].trim_space()
		}
	}

	return name, condition, opens_block
}

// Extract route-to / reply-to targets from a filter rule line.
// A target may be a single host, an "(interface address)" pair, or a
// "{ ... }" round-robin pool. Returns (route_to, reply_to).
// Collect a value token that may be a "{ ... }" or "( ... )" group spanning
// several space-separated tokens. `start` indexes the first value token;
// returns (value, index_after_value).
fn collect_grouped_value(parts []string, start int) (string, int) {
	if start >= parts.len {
		return '', start
	}
	open := parts[start]
	mut close_ch := ''
	if open.starts_with('{') && !open.ends_with('}') {
		close_ch = '}'
	} else if open.starts_with('(') && !open.ends_with(')') {
		close_ch = ')'
	}
	if close_ch == '' {
		return open, start + 1
	}
	mut tparts := []string{}
	mut i := start
	for i < parts.len && !parts[i].ends_with(close_ch) {
		tparts << parts[i]
		i++
	}
	if i < parts.len {
		tparts << parts[i]
		i++
	}
	return tparts.join(' '), i
}

fn parse_rule_routing(line string) (string, string) {
	rule_part, _ := extract_inline_comment(line)
	parts := rule_part.trim_space().split(' ')

	mut route_to := ''
	mut reply_to := ''

	mut i := 0
	for i < parts.len {
		part := parts[i]
		if part == 'route-to' || part == 'reply-to' {
			val, next := collect_grouped_value(parts, i + 1)
			if part == 'route-to' {
				route_to = val
			} else {
				reply_to = val
			}
			i = next
		} else {
			i++
		}
	}

	return route_to, reply_to
}

// Parse the redirection action of a match rule (nat-to / rdr-to / binat-to / af-to).
// Returns the keyword and its target, e.g.
// "match ... nat-to (egress)" -> ("nat-to", "(egress)").
fn parse_match_redirection(line string) (string, string) {
	rule_part, _ := extract_inline_comment(line)
	parts := rule_part.trim_space().split(' ')

	mut redirect_kw := ''
	mut target := ''

	mut i := 0
	for i < parts.len {
		part := parts[i]
		if part in ['nat-to', 'rdr-to', 'binat-to', 'af-to'] {
			redirect_kw = part
			val, next := collect_grouped_value(parts, i + 1)
			target = val
			i = next
		} else {
			i++
		}
	}

	return redirect_kw, target
}

// Extract assorted single-value rule modifiers (user/group/rtable/probability/
// received-on/divert-to and "set prio") from a filter or match rule line.
struct RuleModifiers {
	user        string
	group       string
	rtable      string
	probability string
	received_on string
	divert_to   string
	prio        string
}

fn parse_rule_modifiers(line string) RuleModifiers {
	rule_part, _ := extract_inline_comment(line)
	parts := rule_part.trim_space().split(' ')

	mut user := ''
	mut group := ''
	mut rtable := ''
	mut probability := ''
	mut received_on := ''
	mut divert_to := ''
	mut prio := ''

	mut i := 0
	for i < parts.len {
		match parts[i] {
			'user' {
				user, i = collect_grouped_value(parts, i + 1)
			}
			'group' {
				group, i = collect_grouped_value(parts, i + 1)
			}
			'rtable' {
				rtable, i = collect_grouped_value(parts, i + 1)
			}
			'probability' {
				probability, i = collect_grouped_value(parts, i + 1)
			}
			'received-on' {
				received_on, i = collect_grouped_value(parts, i + 1)
			}
			'divert-to' {
				val, next := collect_grouped_value(parts, i + 1)
				mut dv := val
				mut j := next
				// divert-to may carry a "port <n>" clause
				if j + 1 < parts.len && parts[j] == 'port' {
					dv += ' port ${parts[j + 1]}'
					j += 2
				}
				divert_to = dv
				i = j
			}
			'set' {
				if i + 1 < parts.len && parts[i + 1] == 'prio' {
					prio, i = collect_grouped_value(parts, i + 2)
				} else {
					i++
				}
			}
			else {
				i++
			}
		}
	}

	return RuleModifiers{
		user: user
		group: group
		rtable: rtable
		probability: probability
		received_on: received_on
		divert_to: divert_to
		prio: prio
	}
}

// Parse an include line (e.g., 'include "/etc/pf.macros"' -> "/etc/pf.macros")
fn parse_include_line(line string) string {
	rule_part, _ := extract_inline_comment(line)
	trimmed := rule_part.trim_space()
	if !trimmed.starts_with('include') {
		return ''
	}
	return trimmed[7..].trim_space().trim('"\'')
}

// Parse a load anchor line
// (e.g., 'load anchor "ftp" from "/etc/ftp.conf"' -> ("ftp", "/etc/ftp.conf"))
fn parse_load_anchor_line(line string) (string, string) {
	rule_part, _ := extract_inline_comment(line)
	trimmed := rule_part.trim_space()
	mut name := ''
	mut path := ''
	if !trimmed.starts_with('load anchor') {
		return name, path
	}
	rest := trimmed[11..].trim_space() // after 'load anchor'
	if from_idx := rest.index(' from ') {
		name = rest[..from_idx].trim_space().trim('"\'')
		path = rest[from_idx + 6..].trim_space().trim('"\'')
	} else {
		name = rest.trim('"\'')
	}
	return name, path
}

// Parse option/set line into components (e.g., "set skip on lo" -> ("skip", "on lo"))
fn parse_option_line(line string) (string, string) {
	trimmed := line.trim_space()
	
	// Remove "set " prefix
	if !trimmed.starts_with('set ') {
		return '', ''
	}
	
	rest := trimmed[4..].trim_space() // Remove "set "
	parts := rest.split(' ')
	
	if parts.len == 0 {
		return '', ''
	}
	
	option_name := parts[0]
	option_value := if parts.len > 1 { parts[1..].join(' ') } else { '' }
	
	return option_name, option_value
}

// Parse table line into components (e.g., "table <blocklist> { 97.107.130.116 }" or "table <fleximus.de-dyn> persist")
fn parse_table_line(line string) (string, []string, bool) {
	mut table_name := ''
	mut table_values := []string{}
	mut table_persist := false
	
	// Extract table name from < >
	if line.contains('<') && line.contains('>') {
		start := line.index('<') or { 0 }
		end := line.index('>') or { 0 }
		if end > start {
			table_name = line[start+1..end]
		}
	}
	
	// Check for persist keyword
	if line.contains(' persist') {
		table_persist = true
	}
	
	// Extract values from { } if present
	if line.contains('{') && line.contains('}') {
		start := line.index('{') or { 0 }
		end := line.index('}') or { 0 }
		if end > start {
			values_str := line[start+1..end].trim_space()
			if values_str != '' {
				parts := values_str.split(',')
				for part in parts {
					cleaned := part.trim_space()
					if cleaned != '' {
						table_values << cleaned
					}
				}
			}
		}
	}
	
	return table_name, table_values, table_persist
}

// A single problem found during a check-mode validation pass.
struct ValidationError {
	line_num int
	content  string
	message  string
}

// validate_pf_lines performs a best-effort syntax check over parsed lines.
// It returns one entry per problem found; an empty slice means the input is clean.
// Note: this validates what pfjson can recognize. Lines it cannot classify are
// reported as errors, since the tool cannot vouch for their syntax.
fn validate_pf_lines(lines []PfLine) []ValidationError {
	mut errors := []ValidationError{}
	for line in lines {
		match line.line_type {
			'unknown' {
				errors << ValidationError{
					line_num: line.line_num
					content: line.raw_line
					message: 'unrecognized or unsupported syntax'
				}
			}
			'macro' {
				if line.name == '' {
					errors << ValidationError{
						line_num: line.line_num
						content: line.raw_line
						message: 'macro is missing a name'
					}
				}
			}
			'table' {
				if line.name == '' {
					errors << ValidationError{
						line_num: line.line_num
						content: line.raw_line
						message: 'table is missing a name'
					}
				}
			}
			'rule' {
				if line.action != 'pass' && line.action != 'block' {
					errors << ValidationError{
						line_num: line.line_num
						content: line.raw_line
						message: 'rule must start with "pass" or "block"'
					}
				}
			}
			else {}
		}
	}
	return errors
}

