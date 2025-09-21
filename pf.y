%{
module main
%}

%union {
	str string
	num int
	config PfConfig
	macro PfMacro
	table PfTable
	option PfOption
	rule PfRule
	nat_rule PfNatRule
	scrub_rule PfScrubRule
	comment PfComment
	str_list []string
}

%token <str> IDENTIFIER STRING COMMENT
%token <num> NUMBER
%token ASSIGN
%token LBRACE RBRACE LPAREN RPAREN
%token SEMICOLON COMMA DOT SLASH DASH COLON
%token LT GT

// Keywords
%token SET SKIP SCRUB NAT RDR NO
%token PASS BLOCK IN OUT ALL ON
%token FROM TO PORT PROTO TCP UDP ICMP
%token KEEP STATE LOG TABLE
%token MAX_SRC_CONN MAX_SRC_CONN_RATE

%type <config> pf_config
%type <macro> macro_def
%type <table> table_def
%type <option> option_def
%type <rule> rule_def
%type <nat_rule> nat_rule_def
%type <scrub_rule> scrub_rule_def
%type <comment> comment_def
%type <str_list> string_list port_list

%start pf_config

%%

pf_config:
	  /* empty */ { yyrcvr.lval = PfConfig{} }
	| pf_config macro_def { 
		mut config := $1.config
		config.macros << $2.macro
		yyrcvr.lval = config
	}
	| pf_config table_def {
		mut config := $1.config
		config.tables << $2.table
		yyrcvr.lval = config
	}
	| pf_config option_def {
		mut config := $1.config
		config.options << $2.option
		yyrcvr.lval = config
	}
	| pf_config scrub_rule_def {
		mut config := $1.config
		config.scrub_rules << $2.scrub_rule
		yyrcvr.lval = config
	}
	| pf_config nat_rule_def {
		mut config := $1.config
		config.nat_rules << $2.nat_rule
		yyrcvr.lval = config
	}
	| pf_config rule_def {
		mut config := $1.config
		config.rules << $2.rule
		yyrcvr.lval = config
	}
	| pf_config comment_def {
		mut config := $1.config
		config.comments << $2.comment
		yyrcvr.lval = config
	}
	;

macro_def:
	IDENTIFIER ASSIGN STRING {
		yyrcvr.lval = PfMacro{
			name: $1.str
			value: $3.str
		}
	}
	;

table_def:
	TABLE LT IDENTIFIER GT LBRACE string_list RBRACE {
		yyrcvr.lval = PfTable{
			name: $3.str
			entries: $6.str_list
		}
	}
	;

option_def:
	SET IDENTIFIER STRING {
		yyrcvr.lval = PfOption{
			option: $2.str
			value: $3.str
		}
	}
	| SET SKIP ON IDENTIFIER {
		yyrcvr.lval = PfOption{
			option: 'skip'
			value: $4.str
		}
	}
	;

scrub_rule_def:
	SCRUB IN ON IDENTIFIER ALL {
		yyrcvr.lval = PfScrubRule{
			direction: 'in'
			interface: $4.str
			options: ['all']
		}
	}
	;

nat_rule_def:
	NAT ON IDENTIFIER FROM STRING TO STRING DASH GT LPAREN IDENTIFIER RPAREN {
		yyrcvr.lval = PfNatRule{
			rule_type: 'nat'
			interface: $3.str
			source: $5.str
			destination: $7.str
			target: $11.str
		}
	}
	| NO NAT ON IDENTIFIER FROM STRING TO STRING {
		yyrcvr.lval = PfNatRule{
			rule_type: 'no nat'
			interface: $4.str
			source: $6.str
			destination: $8.str
		}
	}
	| RDR ON IDENTIFIER PROTO TCP FROM STRING TO LPAREN IDENTIFIER RPAREN PORT NUMBER DASH GT IDENTIFIER PORT NUMBER {
		yyrcvr.lval = PfNatRule{
			rule_type: 'rdr'
			interface: $3.str
			protocol: 'tcp'
			source: $7.str
			destination: $11.str
			port: $13.num.str()
			target: $16.str
			target_port: $18.num.str()
		}
	}
	;

rule_def:
	BLOCK IN ALL {
		yyrcvr.lval = PfRule{
			action: 'block'
			direction: 'in'
			interface: 'all'
		}
	}
	| PASS IN ON IDENTIFIER PROTO TCP FROM STRING TO STRING KEEP STATE {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'in'
			interface: $4.str
			protocol: 'tcp'
			source: $8.str
			destination: $10.str
			options: ['keep state']
		}
	}
	| PASS IN ON IDENTIFIER PROTO TCP FROM LT IDENTIFIER GT TO LPAREN IDENTIFIER RPAREN PORT NUMBER {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'in'
			interface: $4.str
			protocol: 'tcp'
			source: '<' + $9.str + '>'
			destination: '(' + $13.str + ')'
			port: $16.num.str()
		}
	}
	| PASS IN ON IDENTIFIER PROTO TCP FROM STRING TO LPAREN IDENTIFIER RPAREN PORT LBRACE port_list RBRACE {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'in'
			interface: $4.str
			protocol: 'tcp'
			source: $8.str
			destination: '(' + $11.str + ')'
			port: '{' + $15.str_list.join(', ') + '}'
		}
	}
	| PASS IN ON IDENTIFIER PROTO ICMP FROM STRING TO STRING {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'in'
			interface: $4.str
			protocol: 'icmp'
			source: $8.str
			destination: $10.str
		}
	}
	| BLOCK IN FROM LT IDENTIFIER GT {
		yyrcvr.lval = PfRule{
			action: 'block'
			direction: 'in'
			source: '<' + $5.str + '>'
		}
	}
	| PASS IN ON IDENTIFIER FROM STRING TO STRING {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'in'
			interface: $4.str
			source: $6.str
			destination: $8.str
		}
	}
	| PASS IN ON IDENTIFIER PROTO UDP FROM STRING TO IDENTIFIER PORT NUMBER {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'in'
			interface: $4.str
			protocol: 'udp'
			source: $8.str
			destination: $10.str
			port: $12.num.str()
		}
	}
	| PASS OUT ALL {
		yyrcvr.lval = PfRule{
			action: 'pass'
			direction: 'out'
			interface: 'all'
		}
	}
	| BLOCK LOG ALL {
		yyrcvr.lval = PfRule{
			action: 'block'
			options: ['log']
			interface: 'all'
		}
	}
	;

string_list:
	  STRING { yyrcvr.lval = [$1.str] }
	| string_list COMMA STRING { yyrcvr.lval = $1.str_list << $3.str }
	;

port_list:
	  NUMBER { yyrcvr.lval = [$1.num.str()] }
	| port_list COMMA NUMBER { yyrcvr.lval = $1.str_list << $3.num.str() }
	;

comment_def:
	COMMENT {
		yyrcvr.lval = PfComment{
			content: $1.str
			position: 'standalone'
		}
	}
	;

%%