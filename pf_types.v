module main

struct PfMacro {
mut:
	name  string
	value string
}

struct PfTable {
mut:
	name    string
	entries []string
	persist bool
}

struct PfOption {
mut:
	option string
	value  string
}

struct PfRule {
mut:
	action      string // 'pass', 'block'
	direction   string // 'in', 'out', 'all'
	quick       bool   // quick rules
	interface   string
	inet_family string // 'inet', 'inet6', or empty
	protocol    string
	source      string
	destination string
	port        string
	options     []string
	label       string
	tag         string
	tagged      string
	dup_to      string // dup-to destination
	comment     string
}

struct PfNatRule {
mut:
	rule_type   string // 'nat', 'rdr', 'no nat'
	interface   string
	protocol    string
	source      string
	destination string
	port        string
	target      string
	target_port string
}

struct PfScrubRule {
mut:
	direction string
	interface string
	options   []string
}

struct PfAntispoof {
mut:
	interface string
	options   []string // like 'log', 'for'
}

struct PfAnchor {
mut:
	name     string
	rules    []PfRule
	options  []string
}

struct PfConfig {
mut:
	macros       []PfMacro
	tables       []PfTable
	options      []PfOption
	scrub_rules  []PfScrubRule
	nat_rules    []PfNatRule
	rules        []PfRule
	antispoof    []PfAntispoof
	anchors      []PfAnchor
	comments     []PfComment
}

struct PfComment {
mut:
	line_num int
	content  string
	position string // 'inline', 'standalone'
}

struct PfConfigWithMeta {
mut:
	metadata FileMetadata
	config   PfConfig
	raw_text string
}

// Line-by-line representation for better comment preservation
struct PfLine {
mut:
	line_num    int
	line_type   string // 'comment', 'macro', 'table', 'option', 'rule', 'nat', 'scrub', 'antispoof', 'blank'
	// Direct fields for structured data (eliminates duplication)
	comment     string @[omitempty] // for comment lines and inline comments
	name        string @[omitempty] // for macro lines (variable name)
	value       string @[omitempty] // for macro lines (variable value) 
	definition  string @[omitempty] // for complex lines that need original content preserved
	
	// Rule-specific fields (for line_type == 'rule')
	action       string @[omitempty] // 'pass', 'block'
	direction    string @[omitempty] // 'in', 'out', ''
	quick        bool   @[omitempty] // quick rules
	log          bool   @[omitempty] // log option for NAT/RDR rules
	
	// Table-specific fields (for line_type == 'table')
	values       []string @[omitempty] // table values array (also reused for other array data)
	persist      bool @[omitempty] // persist flag
	interfaces     []string @[omitempty] // parsed interface array like ['eth0', 'eth1']
	inet_families  []string @[omitempty] // parsed inet family array like ['inet', 'inet6']
	protocols      []string @[omitempty] // parsed protocol array from { tcp, udp }
	sources        []string @[omitempty] // parsed source array from { addr1, addr2 }
	destinations   []string @[omitempty] // parsed destination array from { addr1, addr2 }
	ports        []string @[omitempty] // parsed port array from { 80, 443 }
	options      []string @[omitempty] // rule options like 'keep state'
	label        string @[omitempty] // label
	tag          string @[omitempty] // tag
	tagged       string @[omitempty] // tagged
	dup_to       string @[omitempty] // dup-to destination
	icmp_type    string @[omitempty] // ICMP type for icmp rules
	icmp6_type   string @[omitempty] // ICMP6 type for icmp6 rules
	
	// Option-specific fields (for line_type == 'option')
	option_name  string @[omitempty] // option name (e.g., 'skip')
	option_value string @[omitempty] // option value (e.g., 'on lo', 'limit')
	
	// Antispoof-specific fields (for line_type == 'antispoof')
	// Uses existing interfaces array and log bool fields
	antispoof   []string @[omitempty] // antispoof options like 'quick'
	
	// NAT/RDR-specific fields (for line_type == 'nat' or 'rdr')
	rule_type   string @[omitempty] // NAT rule type like 'nat', 'rdr', 'pass'
	pass        bool   @[omitempty] // pass action for NAT rules
	target      string @[omitempty] // NAT/RDR target
	
	// Raw line content (last field, stored only when formatting is complex)
	raw_line     string @[omitempty] // original line content
}

