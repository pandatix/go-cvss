package gocvss20

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss20, err := ParseVector(tt.Vector)

			assert.Equal(tt.ExpectedCVSS20, cvss20)
			assert.Equal(tt.ExpectedErr, err)

			if cvss20 != nil {
				newVec := cvss20.Vector()
				assert.Equal(tt.Vector, newVec)
			}
		})
	}
}

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS20                     *CVSS20
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392": {
			CVSS20:                     must(ParseVector("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C")),
			ExpectedBaseScore:          7.8,
			ExpectedTemporalScore:      6.4,
			ExpectedEnvironmentalScore: 6.4,
		},
		"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
			CVSS20:                     must(ParseVector("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C")),
			ExpectedBaseScore:          10.0,
			ExpectedTemporalScore:      8.3,
			ExpectedEnvironmentalScore: 8.3,
		},
		"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
			CVSS20:                     must(ParseVector("AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C")),
			ExpectedBaseScore:          6.2,
			ExpectedTemporalScore:      4.9,
			ExpectedEnvironmentalScore: 4.9,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			baseScore := tt.CVSS20.BaseScore()
			temporalScore := tt.CVSS20.TemporalScore()
			environmentalScore := tt.CVSS20.EnvironmentalScore()

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
