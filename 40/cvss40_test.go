package gocvss40

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS40 *CVSS40
	ExpectErr      bool
}{
	"specification-example-B": {
		Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
		ExpectedCVSS40: &CVSS40{
			u0: 0b00100000,
			u1: 0b01100110,
			u2: 0b10100000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
			u6: 0b00000000,
			u7: 0b00000000,
			u8: 0b00000000,
		},
		ExpectErr: false,
	},
	"specification-example-BT": {
		Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A",
		ExpectedCVSS40: &CVSS40{
			u0: 0b00100000,
			u1: 0b01100110,
			u2: 0b10100100,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
			u6: 0b00000000,
			u7: 0b00000000,
			u8: 0b00000000,
		},
		ExpectErr: false,
	},
	// Following test cases are expected to increase the code coverage naturally.
	// They were added to the official specification Section 7.
	// => valid vectors
	"CVSS-BT": {
		Vector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P",
		ExpectedCVSS40: &CVSS40{
			u0: 0b01010101,
			u1: 0b00010001,
			u2: 0b00011000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
			u6: 0b00000000,
			u7: 0b00000000,
			u8: 0b00000000,
		},
		ExpectErr: false,
	},
	"CVSS-BE": {
		Vector: "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H",
		ExpectedCVSS40: &CVSS40{
			u0: 0b10001010,
			u1: 0b10001000,
			u2: 0b01000001,
			u3: 0b01100011,
			u4: 0b01010111,
			u5: 0b10110101,
			u6: 0b00001000,
			u7: 0b00000000,
			u8: 0b00000000,
		},
		ExpectErr: false,
	},
	"CVSS-B with Supplemental": {
		Vector: "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red",
		ExpectedCVSS40: &CVSS40{
			u0: 0b11010101,
			u1: 0b00010001,
			u2: 0b00010100,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
			u6: 0b00000101,
			u7: 0b00101011,
			u8: 0b00000000,
		},
		ExpectErr: false,
	},
	"CVSS-BTE with Supplemental": {
		// Changed IR:X and MVC:X for the test purpose
		Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:H/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:H/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green",
		ExpectedCVSS40: &CVSS40{
			u0: 0b00100000,
			u1: 0b01100110,
			u2: 0b10101111,
			u3: 0b01110100,
			u4: 0b10111100,
			u5: 0b11101110,
			u6: 0b10100010,
			u7: 0b11110110,
			u8: 0b10000000,
		},
		ExpectErr: false,
	},
	// => invalid vectors
	"AV has no valid value F": {
		Vector:         "CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
		ExpectedCVSS40: nil,
		ExpectErr:      true,
	},
	"E defined more than once": {
		Vector:         "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/E:X",
		ExpectedCVSS40: nil,
		ExpectErr:      true,
	},
	"ui is not a valid metric abbreviation": {
		Vector:         "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/ui:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
		ExpectedCVSS40: nil,
		ExpectErr:      true,
	},
	"CVSS v4.0 prefix is missing": {
		Vector:         "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
		ExpectedCVSS40: nil,
		ExpectErr:      true,
	},
	"mandatory VA is missing": {
		Vector:         "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N",
		ExpectedCVSS40: nil,
		ExpectErr:      true,
	},
	"fixed ordering is not respected, CVSS-BTE with Supplemental": {
		Vector:         "CVSS:4.0/AC:L/AV:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/CR:L/IR:X/AR:L/RE:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/AT:N/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/E:U/S:N/AU:N/R:I/V:C/U:Green",
		ExpectedCVSS40: nil,
		ExpectErr:      true,
	},
}

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss40, err := ParseVector(tt.Vector)
			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected error: %t, got %v", tt.ExpectErr, err)
			}

			if err != nil {
				return
			}
			assert.Equal(tt.ExpectedCVSS40, cvss40)
			assert.Equal(tt.Vector, cvss40.Vector())
		})
	}
}

func TestRating(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Score          float64
		ExpectedRating string
		ExpectedErr    error
	}{
		"medium": {
			Score:          5.4,
			ExpectedRating: "MEDIUM",
			ExpectedErr:    nil,
		},
		"high": {
			Score:          7.2,
			ExpectedRating: "HIGH",
			ExpectedErr:    nil,
		},
		"critical": {
			Score:          10.0,
			ExpectedRating: "CRITICAL",
			ExpectedErr:    nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			rating, err := Rating(tt.Score)

			assert.Equal(tt.ExpectedRating, rating)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestScore(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS40               *CVSS40
		ExpectedScore        float64
		ExpectedNomenclature string
	}{
		"full-impact": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
			ExpectedScore:        10.0,
			ExpectedNomenclature: "CVSS-B",
		},
		"no-impact": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"),
			ExpectedScore:        0.0,
			ExpectedNomenclature: "CVSS-B",
		},
		"full-system-no-subsequent": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			ExpectedScore:        9.3,
			ExpectedNomenclature: "CVSS-B",
		},
		"no-system-full-subsequent": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H"),
			ExpectedScore:        7.9,
			ExpectedNomenclature: "CVSS-B",
		},
		"with-t": {
			// This one verify the "full-impact" test case, with Threat intelligence
			// information, is effectively lowered.
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U"),
			ExpectedScore:        9.1,
			ExpectedNomenclature: "CVSS-BT",
		},
		"with-e": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:L/MSA:S"),
			ExpectedScore:        9.8,
			ExpectedNomenclature: "CVSS-BE",
		},
		"smol": {
			// This one only has a funny name :)
			CVSS40:               mustParse("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),
			ExpectedScore:        1.0,
			ExpectedNomenclature: "CVSS-B",
		},
		// Those ones used Clement as a random source.
		// It enabled detecting multiple internal issues to this Go module
		// and a typo in the official calculator a week before publication.
		// This should be kept for regression testing.
		"clement-b": {
			CVSS40:               mustParse("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L"),
			ExpectedScore:        5.2,
			ExpectedNomenclature: "CVSS-B",
		},
		"clement-bte": {
			CVSS40:               mustParse("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAT:P/MPR:N/MVI:H/MVA:N/MSI:H/MSA:N/S:N/V:C/U:Amber"),
			ExpectedScore:        4.7,
			ExpectedNomenclature: "CVSS-BTE",
		},
		"reg-deptheq3eq6": {
			// This test ensures there is no regression on the EQ3/EQ6
			// computations, originally due to a typo.
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L"),
			ExpectedScore:        5.8,
			ExpectedNomenclature: "CVSS-BE",
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			score := tt.CVSS40.Score()
			nom := tt.CVSS40.Nomenclature()

			assert.Equal(tt.ExpectedScore, score)
			assert.Equal(tt.ExpectedNomenclature, nom)
		})
	}
}

func mustParse(vec string) *CVSS40 {
	cvss40, err := ParseVector(vec)
	if err != nil {
		panic(err)
	}
	return cvss40
}
