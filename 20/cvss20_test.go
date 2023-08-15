package gocvss20

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS20 *CVSS20
	ExpectedErr    error
}{
	"CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392": {
		Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001000,
			u1: 0b00100110,
			u2: 0b01110000,
			u3: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
		Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001010,
			u1: 0b10100110,
			u2: 0b01110000,
			u3: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
		Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			u0: 0b00101010,
			u1: 0b10100100,
			u2: 0b01110000,
			u3: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"all-defined": {
		Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001001,
			u1: 0b01100010,
			u2: 0b01111001,
			u3: 0b00101010,
		},
		ExpectedErr: nil,
	},
	"base-and-environmental": {
		// This test covers the case where the temporal group is
		// not defined. This case can be found in the wild (e.g. NIST).
		Vector: "AV:L/AC:M/Au:S/C:N/I:N/A:P/CDP:N/TD:ND/CR:M/IR:ND/AR:ND",
		ExpectedCVSS20: &CVSS20{
			u0: 0b00010100,
			u1: 0b00010000,
			u2: 0b00000010,
			u3: 0b00100000,
		},
		ExpectedErr: nil,
	},
	"invalid-last-metric": {
		Vector:         "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:ND/AR:H/",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrInvalidMetricValue,
	},
	"invalid-metric-value": {
		Vector:         "AV:L/AC:L/Au:M/C:InVaLiD/I:P/A:N",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrInvalidMetricValue,
	},
	"Fuzz_b0c5c63b20b726efad1741c656ed3c1f9ee8c5dc00bb9c938f3e01d11153d51f": {
		// This fuzz crashers enabled detecting that a CVSS v2.0 vector
		// with not any temporal metric defined but some environmental ones
		// does not export the same string as when parsed.
		// It raises the following question: "does the whole metric group must
		// be completly specified in order for the vector to be valid ?". This
		// does not find an answer in the first.org's specification document,
		// but given the fact that the NVD CVSS v2.0 calculator emits a metric
		// group as soon as one of it's metrics is different from "ND", this
		// implementation took the path of unvalidating it because of a lack of
		// metrics.
		Vector:         "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrTooShortVector,
	},
	"Fuzz_b0c5c63b20b726efad1741c656ed3c1f9ee8c5dc00bb9c938f3e01d11153d51f_verified": {
		// This test case proves the possibility of previous fuzz crasher.
		Vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:ND/AR:ND",
		ExpectedCVSS20: &CVSS20{
			u0: 0b01001010,
			u1: 0b10100000,
			u2: 0b00001011,
			u3: 0b00110000,
		},
		ExpectedErr: nil,
	},
	"Fuzz_50620a37c4a7716a77a14602b4bcc7b02e6f751d0a714ed796d9b04402c745ac": {
		// This fuzz crasher enabled detecting that the split function
		// (comming from the optimization step) was doing an Out-Of-Bounds
		// Write (CWE-787) if the vector was only composed of '/'.
		Vector:         "//////////////",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrInvalidMetricOrder,
	},
	"CVE-2022-39213": {
		Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001001,
			u1: 0b01100010,
			u2: 0b01111001,
			u3: 0b00101010,
		},
		ExpectedErr: nil,
	},
}

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

func TestRating(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Score          float64
		ExpectedRating string
		ExpectedErr    error
	}{
		"CVE-2021-4131": {
			Score:          6.8,
			ExpectedRating: "MEDIUM",
			ExpectedErr:    nil,
		},
		"CVE-2017-17627": {
			Score:          7.5,
			ExpectedRating: "HIGH",
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
