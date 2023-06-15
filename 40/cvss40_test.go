package gocvss40

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS40 *CVSS40
	ExpectedErr    error
}{
	"specification-example": {
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
		ExpectedErr: nil,
	},
	"whatever-order": {
		Vector: "CVSS:4.0/UI:N/AC:L/VA:N/AT:N/PR:H/VC:L/SI:N/VI:L/SC:N/AV:N/SA:N",
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
		ExpectedErr: nil,
	},
	"all-defined": {
		Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/SC:N/VI:L/SI:N/VA:N/SA:N/E:A/CR:M/IR:X/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:H/MSC:H/MSI:X/MSA:S/S:N/AU:X/R:I/V:C/RE:M/U:Amber",
		ExpectedCVSS40: &CVSS40{
			u0: 0b00100000,
			u1: 0b01100110,
			u2: 0b10100110,
			u3: 0b00010110,
			u4: 0b10101010,
			u5: 0b01001010,
			u6: 0b00100010,
			u7: 0b01110100,
			u8: 0b11000000,
		},
		ExpectedErr: nil,
	},
}

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss40, err := ParseVector(tt.Vector)

			assert.Equal(tt.ExpectedCVSS40, cvss40)
			assert.Equal(tt.ExpectedErr, err)
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
	}{}

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

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
