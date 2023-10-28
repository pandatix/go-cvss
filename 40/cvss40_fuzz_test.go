package gocvss40

import (
	"math"
	"reflect"
	"regexp"
	"testing"
)

var (
	metricRegex = map[string]string{
		// Base
		"AV": "(\\/AV:[NALP])",
		"AC": "(\\/AC:[LH])",
		"AT": "(\\/AT:[NP])",
		"PR": "(\\/PR:[NLH])",
		"UI": "(\\/UI:[NPA])",
		"VC": "(\\/VC:[HLN])",
		"VI": "(\\/VI:[HLN])",
		"VA": "(\\/VA:[HLN])",
		"SC": "(\\/SC:[HLN])",
		"SI": "(\\/SI:[HLN])",
		"SA": "(\\/SA:[HLN])",
		// Threat
		"E": "(\\/E:[XAPU])?",
		// Environmental
		"CR":  "(\\/CR:[XHML])?",
		"IR":  "(\\/IR:[XHML])?",
		"AR":  "(\\/AR:[XHML])?",
		"MAV": "(\\/MAV:[XNALP])?",
		"MAC": "(\\/MAC:[XLH])?",
		"MAT": "(\\/MAT:[XNP])?",
		"MPR": "(\\/MPR:[XNLH])?",
		"MUI": "(\\/MUI:[XNPA])?",
		"MVC": "(\\/MVC:[XNLH])?",
		"MVI": "(\\/MVI:[XNLH])?",
		"MVA": "(\\/MVA:[XNLH])?",
		"MSC": "(\\/MSC:[XNLH])?",
		"MSI": "(\\/MSI:[XNLHS])?",
		"MSA": "(\\/MSA:[XNLHS])?",
		// Supplemental
		"S":  "(\\/S:[XNP])?",
		"AU": "(\\/AU:[XNY])?",
		"R":  "(\\/R:[XAUI])?",
		"V":  "(\\/V:[XDC])?",
		"RE": "(\\/RE:[XLMH])?",
		"U":  "(\\/U:(?:X|Clear|Green|Amber|Red))?",
	}
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

func FuzzParseVector(f *testing.F) {
	rgx := "CVSS:4[.]0"
	for _, group := range order {
		for _, metric := range group {
			rgx += metricRegex[metric]
		}
	}
	rgx = "^" + rgx + "$"
	regex := regexp.MustCompile(rgx)

	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss40, err := ParseVector(vector)
		match := regex.Match([]byte(vector))

		if (err != nil) == match {
			t.Fatalf("vector %s is %t according to the regex but got error %v", vector, match, err)
		}
		if err != nil {
			if cvss40 != nil {
				t.Fatal("not supposed to get a CVSS40 when en error is returned")
			}
			return
		}

		// Compute score
		score := cvss40.Score()
		if score < 0.0 || score > 10.0 || math.IsNaN(score) {
			t.Fatalf("score is out of bounds: %.1f", score)
		}

		// Ensure produced string vector is valid
		cvss40vector := cvss40.Vector()
		newCVSS40, _ := ParseVector(cvss40vector)
		if !reflect.DeepEqual(cvss40, newCVSS40) {
			t.Fatalf("cvss40's vector %s does not give as much info as input vector %s", cvss40vector, vector)
		}
	})
}
