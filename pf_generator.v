module main

fn generate_pf_conf_from_lines(lines []PfLine) !string {
	mut output := []string{}
	
	for line in lines {
		match line.line_type {
			'blank' {
				output << ''
			}
			'comment' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					output << '#${line.comment}'
				}
			}
			'macro' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					output << '${line.name} = "${line.value}"'
				}
			}
			'table' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut table_line := 'table <${line.name}>'
					if line.persist {
						table_line += ' persist'
					} else if line.values.len > 0 {
						table_line += ' { ${line.values.join(', ')} }'
					}
					output << table_line
				}
			}
			'option' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					output << 'set ${line.option_name} ${line.option_value}'
				}
			}
			'antispoof' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut antispoof_line := 'antispoof'
					if line.log {
						antispoof_line += ' log'
					}
					if line.antispoof.len > 0 {
						antispoof_line += ' ${line.antispoof.join(' ')}'
					}
					if line.interfaces.len > 0 {
						antispoof_line += ' for ${line.interfaces[0]}'
					}
					output << antispoof_line
				}
			}
			'nat', 'rdr', 'rule' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					// Reconstruct rule from parsed components
					mut rule_parts := []string{}
					
					if line.line_type == 'nat' || line.line_type == 'rdr' {
						if line.rule_type != '' {
							rule_parts << line.rule_type
						} else {
							rule_parts << line.line_type
						}
					} else {
						rule_parts << line.action
					}
					
					if line.direction != '' {
						rule_parts << line.direction
					}
					
					if line.quick {
						rule_parts << 'quick'
					}
					
					if line.interfaces.len > 0 {
						rule_parts << 'on ${line.interfaces.join(' ')}'
					}
					
					if line.inet_families.len > 0 {
						rule_parts << line.inet_families.join(' ')
					}
					
					if line.protocols.len > 0 {
						if line.protocols.len == 1 {
							rule_parts << 'proto ${line.protocols[0]}'
						} else {
							rule_parts << 'proto { ${line.protocols.join(', ')} }'
						}
					}
					
					if line.sources.len > 0 {
						if line.sources.len == 1 {
							rule_parts << 'from ${line.sources[0]}'
						} else {
							rule_parts << 'from { ${line.sources.join(', ')} }'
						}
					}
					
					if line.destinations.len > 0 {
						if line.destinations.len == 1 {
							rule_parts << 'to ${line.destinations[0]}'
						} else {
							rule_parts << 'to { ${line.destinations.join(', ')} }'
						}
					}
					
					if line.ports.len > 0 {
						if line.ports.len == 1 {
							rule_parts << 'port ${line.ports[0]}'
						} else {
							rule_parts << 'port { ${line.ports.join(', ')} }'
						}
					}
					
					if line.icmp_type != '' {
						rule_parts << 'icmp-type ${line.icmp_type}'
					}
					
					if line.icmp6_type != '' {
						rule_parts << 'icmp6-type ${line.icmp6_type}'
					}
					
					if line.target != '' {
						rule_parts << '-> ${line.target}'
					}
					
					if line.options.len > 0 {
						rule_parts << line.options.join(' ')
					}
					
					if line.label != '' {
						rule_parts << 'label ${line.label}'
					}
					
					if line.tag != '' {
						rule_parts << 'tag ${line.tag}'
					}
					
					if line.tagged != '' {
						rule_parts << 'tagged ${line.tagged}'
					}
					
					if line.dup_to != '' {
						rule_parts << 'dup-to ${line.dup_to}'
					}
					
					mut rule_line := rule_parts.join(' ')
					
					if line.comment != '' {
						rule_line += ' # ${line.comment}'
					}
					
					output << rule_line
				}
			}
			else {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					output << '# Unknown line type: ${line.line_type}'
				}
			}
		}
	}
	
	return output.join('\n')
}

fn generate_pf_conf(config PfConfig) !string {
	mut lines := []string{}
	
	// Add comments
	for comment in config.comments {
		lines << comment.content
	}
	
	// Add macros
	for macro in config.macros {
		lines << '${macro.name} = "${macro.value}"'
	}
	
	// Add options
	for option in config.options {
		lines << 'set ${option.option} ${option.value}'
	}
	
	// Add tables
	for table in config.tables {
		if table.persist {
			lines << 'table <${table.name}> persist'
		} else {
			lines << 'table <${table.name}> { ${table.entries.join(', ')} }'
		}
	}
	
	// Add NAT rules
	for nat_rule in config.nat_rules {
		mut rule_line := nat_rule.rule_type
		
		if nat_rule.interface != '' {
			rule_line += ' on ${nat_rule.interface}'
		}
		
		if nat_rule.protocol != '' {
			rule_line += ' proto ${nat_rule.protocol}'
		}
		
		if nat_rule.source != '' {
			rule_line += ' from ${nat_rule.source}'
		}
		
		if nat_rule.destination != '' {
			rule_line += ' to ${nat_rule.destination}'
		}
		
		if nat_rule.port != '' {
			rule_line += ' port ${nat_rule.port}'
		}
		
		if nat_rule.target != '' {
			rule_line += ' -> ${nat_rule.target}'
		}
		
		if nat_rule.target_port != '' {
			rule_line += ' port ${nat_rule.target_port}'
		}
		
		lines << rule_line
	}
	
	// Add rules
	for rule in config.rules {
		mut rule_line := rule.action
		
		if rule.direction != '' {
			rule_line += ' ${rule.direction}'
		}
		
		if rule.quick {
			rule_line += ' quick'
		}
		
		if rule.interface != '' {
			rule_line += ' on ${rule.interface}'
		}
		
		if rule.protocol != '' {
			rule_line += ' proto ${rule.protocol}'
		}
		
		if rule.source != '' {
			rule_line += ' from ${rule.source}'
		}
		
		if rule.destination != '' {
			rule_line += ' to ${rule.destination}'
		}
		
		if rule.port != '' {
			rule_line += ' port ${rule.port}'
		}
		
		// Check if 'keep state' is in options
		for option in rule.options {
			if option.contains('keep state') {
				rule_line += ' keep state'
				break
			}
		}
		
		lines << rule_line
	}
	
	return lines.join('\n')
}