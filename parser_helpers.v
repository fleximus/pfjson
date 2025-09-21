module main

struct ParseResult {
	rule       PfRule
	next_index int
}

fn parse_rule(tokens []Token, start_index int) !ParseResult {
	mut i := start_index
	mut rule := PfRule{}
	
	if i >= tokens.len {
		return error('Unexpected end of tokens')
	}
	
	rule.action = tokens[i].value
	i++
	
	for i < tokens.len {
		token := tokens[i]
		
		match token.type_ {
			.in_, .out {
				rule.direction = token.value
				i++
			}
			.all {
				if rule.interface == '' {
					rule.interface = 'all'
				}
				i++
			}
			.on {
				if i + 1 < tokens.len {
					i++
					rule.interface = tokens[i].value
					i++
				} else {
					i++
				}
			}
			.proto {
				if i + 1 < tokens.len {
					i++
					rule.protocol = tokens[i].value
					i++
				} else {
					i++
				}
			}
			.from {
				if i + 1 < tokens.len {
					i++
					addr, new_i := parse_address_or_table(tokens, i)
					rule.source = addr
					i = new_i
				} else {
					i++
				}
			}
			.to {
				if i + 1 < tokens.len {
					i++
					addr, new_i := parse_address_or_table(tokens, i)
					rule.destination = addr
					i = new_i
				} else {
					i++
				}
			}
			.port {
				if i + 1 < tokens.len {
					i++
					port_spec, new_i := parse_port_spec(tokens, i)
					rule.port = port_spec
					i = new_i
				} else {
					i++
				}
			}
			.keep {
				if i + 1 < tokens.len && tokens[i + 1].type_ == .state {
					rule.options << 'keep state'
					i += 2
				} else {
					i++
				}
			}
			.log {
				rule.options << 'log'
				i++
			}
			.quick {
				rule.quick = true
				i++
			}
			.inet {
				rule.inet_family = 'inet'
				i++
			}
			.inet6 {
				rule.inet_family = 'inet6'
				i++
			}
			.label {
				if i + 1 < tokens.len {
					i++
					rule.label = tokens[i].value
					i++
				} else {
					i++
				}
			}
			.tag {
				if i + 1 < tokens.len {
					i++
					rule.tag = tokens[i].value
					i++
				} else {
					i++
				}
			}
			.tagged {
				if i + 1 < tokens.len {
					i++
					rule.tagged = tokens[i].value
					i++
				} else {
					i++
				}
			}
			.dup_to {
				if i + 1 < tokens.len {
					i++
					// Parse dup-to destination which can be (interface destination)
					if tokens[i].type_ == .lparen {
						mut dup_parts := []string{}
						i++ // skip '('
						for i < tokens.len && tokens[i].type_ != .rparen {
							dup_parts << tokens[i].value
							i++
						}
						if i < tokens.len && tokens[i].type_ == .rparen {
							i++ // skip ')'
						}
						rule.dup_to = '(${dup_parts.join(" ")})'
					} else {
						rule.dup_to = tokens[i].value
						i++
					}
				} else {
					i++
				}
			}
			.comment {
				rule.comment = token.value
				i++
			}
			.eof {
				break
			}
			else {
				if is_rule_end_token(token.type_) {
					break
				}
				i++
			}
		}
	}
	
	return ParseResult{
		rule: rule
		next_index: i
	}
}

fn parse_address_or_table(tokens []Token, i int) (string, int) {
	if i >= tokens.len {
		return '', i
	}
	
	token := tokens[i]
	
	match token.type_ {
		.lt {
			// Table reference like <tablename>
			if i + 2 < tokens.len && tokens[i + 2].type_ == .gt {
				result := '<${tokens[i + 1].value}>'
				return result, i + 3
			}
		}
		.lparen {
			// Interface reference like ($ext_if)
			if i + 2 < tokens.len && tokens[i + 2].type_ == .rparen {
				result := '(${tokens[i + 1].value})'
				return result, i + 3
			}
		}
		.lbrace {
			// Address list like { addr1, addr2, addr3 } or { !addr1, !addr2 }
			mut parts := []string{}
			mut j := i + 1 // skip '{'
			
			for j < tokens.len && tokens[j].type_ != .rbrace {
				if tokens[j].type_ == .comma {
					j++ // skip comma
					continue
				}
				
				// Handle negation with !
				if j < tokens.len && tokens[j].value == '!' {
					if j + 1 < tokens.len {
						parts << '!${tokens[j + 1].value}'
						j += 2
					} else {
						j++
					}
				} else {
					parts << tokens[j].value
					j++
				}
			}
			
			if j < tokens.len && tokens[j].type_ == .rbrace {
				j++ // skip '}'
			}
			
			result := '{ ${parts.join(", ")} }'
			return result, j
		}
		.string_literal, .identifier {
			// Regular address or variable
			result := token.value
			return result, i + 1
		}
		else {}
	}
	
	return token.value, i + 1
}

fn parse_port_spec(tokens []Token, i int) (string, int) {
	if i >= tokens.len {
		return '', i
	}
	
	token := tokens[i]
	
	match token.type_ {
		.lbrace {
			// Port list like { 80, 443 }
			mut ports := []string{}
			mut j := i + 1
			for j < tokens.len && tokens[j].type_ != .rbrace {
				if tokens[j].type_ == .number {
					ports << tokens[j].value
				}
				j++
			}
			if j < tokens.len && tokens[j].type_ == .rbrace {
				j++
			}
			return '{${ports.join(', ')}}', j
		}
		.number {
			// Single port
			mut result := token.value
			// Check for port range
			if i + 2 < tokens.len && tokens[i + 1].type_ == .colon {
				result += ':${tokens[i + 2].value}'
				return result, i + 3
			} else {
				return result, i + 1
			}
		}
		else {
			return token.value, i + 1
		}
	}
}

fn is_rule_end_token(token_type TokenType) bool {
	return token_type in [
		.pass,
		.block,
		.set,
		.table,
		.nat,
		.rdr,
		.scrub,
		.eof
	]
}

fn is_rule_start_token(token_type TokenType) bool {
	return token_type in [
		.pass,
		.block,
		.set,
		.table,
		.nat,
		.rdr,
		.scrub,
		.comment,
		.eof
	]
}