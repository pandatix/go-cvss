package gocvss30

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS30 *CVSS30
	ExpectedErr    error
}{
	"CVE-2021-4131": {
		Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
		ExpectedCVSS30: &CVSS30{
			u0: 0b00000101,
			u1: 0b00010000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVE-2020-2931": {
		Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS30: &CVSS30{
			u0: 0b00000000,
			u1: 0b00000000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"all-defined": {
		Vector: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
		ExpectedCVSS30: &CVSS30{
			u0: 0b00101000,
			u1: 0b00101001,
			u2: 0b10001010,
			u3: 0b10100101,
			u4: 0b01011001,
			u5: 0b01010000,
		},
		ExpectedErr: nil,
	},
	"whatever-order": {
		Vector: "CVSS:3.0/I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:A/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U",
		ExpectedCVSS30: &CVSS30{
			u0: 0b01101000,
			u1: 0b00101001,
			u2: 0b10001010,
			u3: 0b10100101,
			u4: 0b01011001,
			u5: 0b01010000,
		},
		ExpectedErr: nil,
	},
}

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss30, err := ParseVector(tt.Vector)

			assert.Equal(tt.ExpectedCVSS30, cvss30)
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
		"CVE-2021-4131": {
			Score:          6.5,
			ExpectedRating: "MEDIUM",
			ExpectedErr:    nil,
		},
		"CVE-2020-2931": {
			Score:          9.8,
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

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS30                     *CVSS30
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVE-2021-4131": {
			CVSS30:                     must(ParseVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N")),
			ExpectedBaseScore:          6.5,
			ExpectedTemporalScore:      6.5,
			ExpectedEnvironmentalScore: 6.5,
		},
		"CVE-2020-2931": {
			CVSS30:                     must(ParseVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
			ExpectedBaseScore:          9.8,
			ExpectedTemporalScore:      9.8,
			ExpectedEnvironmentalScore: 9.8,
		},
		"all-defined": {
			CVSS30:                     must(ParseVector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/E:F/RL:U/RC:R/CR:H/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H")),
			ExpectedBaseScore:          7.1,
			ExpectedTemporalScore:      6.7,
			ExpectedEnvironmentalScore: 9.4,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			baseScore := tt.CVSS30.BaseScore()
			temporalScore := tt.CVSS30.TemporalScore()
			environmentalScore := tt.CVSS30.EnvironmentalScore()

			assert.Equal(tt.ExpectedBaseScore, baseScore)
			assert.Equal(tt.ExpectedTemporalScore, temporalScore)
			assert.Equal(tt.ExpectedEnvironmentalScore, environmentalScore)
		})
	}
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
