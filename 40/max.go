package gocvss40

var highestSeverityVectors = map[int]map[int][]string{
	// Table 24 - EQ1
	1: {
		0: []string{"AV:N/PR:N/UI:N"},
		1: []string{"AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"},
		2: []string{"AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"},
	},
	// Table 25 - EQ2
	2: {
		0: []string{"AC:L/AT:N"},
		1: []string{"AC:L/AT:P", "AC:H/AT:N"},
	},
	// Table 27 - EQ4
	4: {
		0: []string{"SC:H/SI:S/SA:S"},
		1: []string{"SC:H/SI:H/SA:H"},
		2: []string{"SC:L/SI:L/SA:L"},
	},
	// Table 28 - EQ5
	5: {
		0: []string{"E:A"},
		1: []string{"E:P"},
		2: []string{"E:U"},
	},
}

// Table 30
var highestSeverityVectorsEQ3EQ6 = map[int]map[int][]string{
	0: {
		0: []string{"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"},
		1: []string{"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"},
	},
	1: {
		0: []string{"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"},
		1: []string{
			"VC:H/VI:L/VA:H/CR:M/IR:H/AR:M",
			"VC:H/VI:L/VA:L/CR:M/IR:H/AR:H",
			"VC:L/VI:H/VA:H/CR:H/IR:M/AR:M",
			"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H",
			"VC:L/VI:L/VA:H/CR:H/IR:H/AR:M",
		},
	},
	2: {
		1: []string{"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"},
	},
}
