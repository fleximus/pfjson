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
			'scrub' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut scrub_line := 'scrub'
					if line.direction != '' {
						scrub_line += ' ${line.direction}'
					}
					if line.interfaces.len > 0 {
						scrub_line += ' on ${line.interfaces[0]}'
					}
					if line.options.len > 0 {
						scrub_line += ' ${line.options.join(' ')}'
					}
					output << scrub_line
				}
			}
			'anchor' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut anchor_line := 'anchor'
					if line.name != '' {
						anchor_line += ' "${line.name}"'
					}
					if line.definition != '' {
						anchor_line += ' ${line.definition}'
					}
					if line.block_open {
						anchor_line += ' {'
					}
					output << anchor_line
				}
			}
			'anchor-close' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					output << '}'
				}
			}
			'altq' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut altq_line := 'altq'
					if line.interfaces.len > 0 {
						altq_line += ' on ${line.interfaces[0]}'
					}
					if line.definition != '' {
						altq_line += ' ${line.definition}'
					}
					if line.values.len > 0 {
						altq_line += ' queue { ${line.values.join(', ')} }'
					}
					output << altq_line
				}
			}
			'queue' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut queue_line := 'queue ${line.name}'
					if line.interfaces.len > 0 {
						queue_line += ' on ${line.interfaces[0]}'
					}
					if line.definition != '' {
						queue_line += ' ${line.definition}'
					}
					if line.values.len > 0 {
						queue_line += ' { ${line.values.join(', ')} }'
					}
					output << queue_line
				}
			}
			'include' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					output << 'include "${line.value}"'
				}
			}
			'load' {
				if line.raw_line != '' {
					output << line.raw_line
				} else {
					mut load_line := 'load anchor "${line.name}"'
					if line.value != '' {
						load_line += ' from "${line.value}"'
					}
					output << load_line
				}
			}
			'nat', 'rdr', 'rule', 'match' {
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

					if line.flags != '' {
						rule_parts << 'flags ${line.flags}'
					}

					if line.target != '' {
						if line.line_type == 'match' && line.rule_type != '' {
							// match redirection: nat-to / rdr-to / binat-to / af-to
							rule_parts << '${line.rule_type} ${line.target}'
						} else {
							rule_parts << '-> ${line.target}'
						}
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

					if line.route_to != '' {
						rule_parts << 'route-to ${line.route_to}'
					}

					if line.reply_to != '' {
						rule_parts << 'reply-to ${line.reply_to}'
					}

					if line.user != '' {
						rule_parts << 'user ${line.user}'
					}

					if line.group != '' {
						rule_parts << 'group ${line.group}'
					}

					if line.received_on != '' {
						rule_parts << 'received-on ${line.received_on}'
					}

					if line.divert_to != '' {
						rule_parts << 'divert-to ${line.divert_to}'
					}

					if line.probability != '' {
						rule_parts << 'probability ${line.probability}'
					}

					if line.rtable != '' {
						rule_parts << 'rtable ${line.rtable}'
					}

					if line.prio != '' {
						rule_parts << 'set prio ${line.prio}'
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
