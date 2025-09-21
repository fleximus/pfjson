module main

enum TokenType {
	eof
	identifier
	string_literal
	number
	comment
	assign
	lbrace
	rbrace
	lparen
	rparen
	semicolon
	comma
	dot
	slash
	dash
	colon
	lt
	gt
	exclamation
	// Keywords
	set
	skip
	scrub
	nat
	rdr
	no
	pass
	block
	in_
	out
	all
	on
	from
	to
	port
	proto
	tcp
	udp
	icmp
	keep
	state
	log
	table
	max_src_conn
	max_src_conn_rate
	// Missing advanced keywords
	antispoof
	anchor
	match
	load
	quick
	label
	tag
	tagged
	dup_to
	inet
	inet6
	icmp_type
	icmp6_type
	for_
	persist
	flags
	any
}

struct Token {
	type_ TokenType
	value string
	line  int
	col   int
}

struct Lexer {
mut:
	input    string
	position int
	line     int
	col      int
	tokens   []Token
}

fn new_lexer(input string) Lexer {
	return Lexer{
		input: input
		position: 0
		line: 1
		col: 1
		tokens: []Token{}
	}
}

fn (mut lexer Lexer) current_char() u8 {
	if lexer.position >= lexer.input.len {
		return 0
	}
	return lexer.input[lexer.position]
}

fn (mut lexer Lexer) peek_char() u8 {
	if lexer.position + 1 >= lexer.input.len {
		return 0
	}
	return lexer.input[lexer.position + 1]
}

fn (mut lexer Lexer) advance() {
	if lexer.current_char() == `\n` {
		lexer.line++
		lexer.col = 1
	} else {
		lexer.col++
	}
	lexer.position++
}

fn (mut lexer Lexer) skip_whitespace() {
	for lexer.current_char() in [` `, `\t`, `\r`] {
		lexer.advance()
	}
}

fn (mut lexer Lexer) read_identifier() string {
	start := lexer.position
	for lexer.current_char().is_alnum() || lexer.current_char() in [`_`, `-`, `.`, `$`, `/`, `:`] {
		lexer.advance()
	}
	return lexer.input[start..lexer.position]
}

fn (mut lexer Lexer) read_string() string {
	lexer.advance() // skip opening quote
	start := lexer.position
	for lexer.current_char() != `"` && lexer.current_char() != 0 {
		lexer.advance()
	}
	value := lexer.input[start..lexer.position]
	if lexer.current_char() == `"` {
		lexer.advance() // skip closing quote
	}
	return value
}

fn (mut lexer Lexer) read_number() string {
	start := lexer.position
	for lexer.current_char().is_digit() || lexer.current_char() == `.` {
		lexer.advance()
	}
	return lexer.input[start..lexer.position]
}

fn (mut lexer Lexer) read_comment() string {
	lexer.advance() // skip #
	start := lexer.position
	for lexer.current_char() != `\n` && lexer.current_char() != 0 {
		lexer.advance()
	}
	return lexer.input[start..lexer.position]
}

fn (mut lexer Lexer) read_ip_range() string {
	start := lexer.position
	for lexer.current_char().is_digit() || lexer.current_char() in [`.`, `/`] {
		lexer.advance()
	}
	return lexer.input[start..lexer.position]
}

fn keyword_type(word string) TokenType {
	match word {
		'set' { return TokenType.set }
		'skip' { return TokenType.skip }
		'scrub' { return TokenType.scrub }
		'nat' { return TokenType.nat }
		'rdr' { return TokenType.rdr }
		'no' { return TokenType.no }
		'pass' { return TokenType.pass }
		'block' { return TokenType.block }
		'in' { return TokenType.in_ }
		'out' { return TokenType.out }
		'all' { return TokenType.all }
		'on' { return TokenType.on }
		'from' { return TokenType.from }
		'to' { return TokenType.to }
		'port' { return TokenType.port }
		'proto' { return TokenType.proto }
		'tcp' { return TokenType.tcp }
		'udp' { return TokenType.udp }
		'icmp' { return TokenType.icmp }
		'keep' { return TokenType.keep }
		'state' { return TokenType.state }
		'log' { return TokenType.log }
		'table' { return TokenType.table }
		'max-src-conn' { return TokenType.max_src_conn }
		'max-src-conn-rate' { return TokenType.max_src_conn_rate }
		'antispoof' { return TokenType.antispoof }
		'anchor' { return TokenType.anchor }
		'match' { return TokenType.match }
		'load' { return TokenType.load }
		'quick' { return TokenType.quick }
		'label' { return TokenType.label }
		'tag' { return TokenType.tag }
		'tagged' { return TokenType.tagged }
		'dup-to' { return TokenType.dup_to }
		'inet' { return TokenType.inet }
		'inet6' { return TokenType.inet6 }
		'icmp-type' { return TokenType.icmp_type }
		'icmp6-type' { return TokenType.icmp6_type }
		'for' { return TokenType.for_ }
		'persist' { return TokenType.persist }
		'flags' { return TokenType.flags }
		'any' { return TokenType.any }
		else { return TokenType.identifier }
	}
}

fn (mut lexer Lexer) next_token() Token {
	for {
		lexer.skip_whitespace()
		
		ch := lexer.current_char()
		line := lexer.line
		col := lexer.col
		
		match ch {
			0 {
				return Token{TokenType.eof, '', line, col}
			}
			`\n` {
				lexer.advance()
				continue
			}
			`#` {
				comment := lexer.read_comment()
				return Token{TokenType.comment, comment, line, col}
			}
			`"` {
				value := lexer.read_string()
				return Token{TokenType.string_literal, value, line, col}
			}
			`=` {
				lexer.advance()
				return Token{TokenType.assign, '=', line, col}
			}
			`{` {
				lexer.advance()
				return Token{TokenType.lbrace, '{', line, col}
			}
			`}` {
				lexer.advance()
				return Token{TokenType.rbrace, '}', line, col}
			}
			`(` {
				lexer.advance()
				return Token{TokenType.lparen, '(', line, col}
			}
			`)` {
				lexer.advance()
				return Token{TokenType.rparen, ')', line, col}
			}
			`;` {
				lexer.advance()
				return Token{TokenType.semicolon, ';', line, col}
			}
			`,` {
				lexer.advance()
				return Token{TokenType.comma, ',', line, col}
			}
			`.` {
				if lexer.peek_char().is_digit() {
					value := lexer.read_number()
					return Token{TokenType.number, value, line, col}
				}
				lexer.advance()
				return Token{TokenType.dot, '.', line, col}
			}
			`/` {
				lexer.advance()
				return Token{TokenType.slash, '/', line, col}
			}
			`-` {
				if lexer.peek_char() == `>` {
					lexer.advance()
					lexer.advance()
					return Token{TokenType.dash, '->', line, col}
				}
				lexer.advance()
				return Token{TokenType.dash, '-', line, col}
			}
			`:` {
				lexer.advance()
				return Token{TokenType.colon, ':', line, col}
			}
			`<` {
				lexer.advance()
				return Token{TokenType.lt, '<', line, col}
			}
			`>` {
				lexer.advance()
				return Token{TokenType.gt, '>', line, col}
			}
			`!` {
				lexer.advance()
				return Token{TokenType.exclamation, '!', line, col}
			}
			else {
				if ch.is_letter() || ch == `_` || ch == `$` {
					value := lexer.read_identifier()
					token_type := keyword_type(value)
					return Token{token_type, value, line, col}
				} else if ch.is_digit() {
					value := lexer.read_number()
					return Token{TokenType.number, value, line, col}
				} else {
					lexer.advance()
					continue
				}
			}
		}
	}
	return Token{TokenType.eof, '', 0, 0}
}

fn (mut lexer Lexer) tokenize() []Token {
	mut tokens := []Token{}
	
	for {
		token := lexer.next_token()
		tokens << token
		if token.type_ == TokenType.eof {
			break
		}
	}
	
	lexer.tokens = tokens
	return tokens
}