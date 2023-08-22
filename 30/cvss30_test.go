package gocvss30

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
