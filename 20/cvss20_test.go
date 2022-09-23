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
			base: base{
				accessVector:          "N",
				accessComplexity:      "L",
				authentication:        "N",
				confidentialityImpact: "N",
				integrityImpact:       "N",
				availabilityImpact:    "C",
			},
			temporal: temporal{
				exploitability:   "F",
				remediationLevel: "OF",
				reportConfidence: "C",
			},
			environmental: environmental{
				collateralDamagePotential:  "ND",
				targetDistribution:         "ND",
				confidentialityRequirement: "ND",
				integrityRequirement:       "ND",
				availabilityRequirement:    "ND",
			},
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
		Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			base: base{
				accessVector:          "N",
				accessComplexity:      "L",
				authentication:        "N",
				confidentialityImpact: "C",
				integrityImpact:       "C",
				availabilityImpact:    "C",
			},
			temporal: temporal{
				exploitability:   "F",
				remediationLevel: "OF",
				reportConfidence: "C",
			},
			environmental: environmental{
				collateralDamagePotential:  "ND",
				targetDistribution:         "ND",
				confidentialityRequirement: "ND",
				integrityRequirement:       "ND",
				availabilityRequirement:    "ND",
			},
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
		Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			base: base{
				accessVector:          "L",
				accessComplexity:      "H",
				authentication:        "N",
				confidentialityImpact: "C",
				integrityImpact:       "C",
				availabilityImpact:    "C",
			},
			temporal: temporal{
				exploitability:   "POC",
				remediationLevel: "OF",
				reportConfidence: "C",
			},
			environmental: environmental{
				collateralDamagePotential:  "ND",
				targetDistribution:         "ND",
				confidentialityRequirement: "ND",
				integrityRequirement:       "ND",
				availabilityRequirement:    "ND",
			},
		},
		ExpectedErr: nil,
	},
	"all-defined": {
		Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M",
		ExpectedCVSS20: &CVSS20{
			base: base{
				accessVector:          "N",
				accessComplexity:      "L",
				authentication:        "N",
				confidentialityImpact: "P",
				integrityImpact:       "P",
				availabilityImpact:    "C",
			},
			temporal: temporal{
				exploitability:   "U",
				remediationLevel: "OF",
				reportConfidence: "C",
			},
			environmental: environmental{
				collateralDamagePotential:  "MH",
				targetDistribution:         "H",
				confidentialityRequirement: "M",
				integrityRequirement:       "M",
				availabilityRequirement:    "M",
			},
		},
		ExpectedErr: nil,
	},
	"base-and-environmental": {
		// This test covers the case where the temporal group is
		// not defined. This case can be found in the wild (e.g. NIST).
		Vector: "AV:L/AC:M/Au:S/C:N/I:N/A:P/CDP:N/TD:ND/CR:M/IR:ND/AR:ND",
		ExpectedCVSS20: &CVSS20{
			base: base{
				accessVector:          "L",
				accessComplexity:      "M",
				authentication:        "S",
				confidentialityImpact: "N",
				integrityImpact:       "N",
				availabilityImpact:    "P",
			},
			temporal: temporal{
				exploitability:   "ND",
				remediationLevel: "ND",
				reportConfidence: "ND",
			},
			environmental: environmental{
				collateralDamagePotential:  "N",
				targetDistribution:         "ND",
				confidentialityRequirement: "M",
				integrityRequirement:       "ND",
				availabilityRequirement:    "ND",
			},
		},
		ExpectedErr: nil,
	},
	"Fuzz_b0c5c63b20b726efad1741c656ed3c1f9ee8c5dc00bb9c938f3e01d11153d51f": {
		// This fuzz crashers enabled detecting that a CVSS v2.0 vector
		// with not any temporal metric defined but some environmental ones
		// does not export the same string as when parsed.
		// It raises the following question: "does the whole metric group must
		// me completly specified in order to the vector to be valid ?". This
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
			base: base{
				accessVector:          "A",
				accessComplexity:      "L",
				authentication:        "N",
				confidentialityImpact: "C",
				integrityImpact:       "C",
				availabilityImpact:    "C",
			},
			temporal: temporal{
				exploitability:   "ND",
				remediationLevel: "ND",
				reportConfidence: "ND",
			},
			environmental: environmental{
				collateralDamagePotential:  "H",
				targetDistribution:         "H",
				confidentialityRequirement: "H",
				integrityRequirement:       "ND",
				availabilityRequirement:    "ND",
			},
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

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS20                     *CVSS20
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392": {
			CVSS20: &CVSS20{
				base: base{
					accessVector:          "N",
					accessComplexity:      "L",
					authentication:        "N",
					confidentialityImpact: "N",
					integrityImpact:       "N",
					availabilityImpact:    "C",
				},
				temporal: temporal{
					exploitability:   "F",
					remediationLevel: "OF",
					reportConfidence: "C",
				},
				environmental: environmental{
					collateralDamagePotential:  "ND",
					targetDistribution:         "ND",
					confidentialityRequirement: "ND",
					integrityRequirement:       "ND",
					availabilityRequirement:    "ND",
				},
			},
			ExpectedBaseScore:          7.8,
			ExpectedTemporalScore:      6.4,
			ExpectedEnvironmentalScore: 6.4,
		},
		"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
			CVSS20: &CVSS20{
				base: base{
					accessVector:          "N",
					accessComplexity:      "L",
					authentication:        "N",
					confidentialityImpact: "C",
					integrityImpact:       "C",
					availabilityImpact:    "C",
				},
				temporal: temporal{
					exploitability:   "F",
					remediationLevel: "OF",
					reportConfidence: "C",
				},
				environmental: environmental{
					collateralDamagePotential:  "ND",
					targetDistribution:         "ND",
					confidentialityRequirement: "ND",
					integrityRequirement:       "ND",
					availabilityRequirement:    "ND",
				},
			},
			ExpectedBaseScore:          10.0,
			ExpectedTemporalScore:      8.3,
			ExpectedEnvironmentalScore: 8.3,
		},
		"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
			CVSS20: &CVSS20{
				base: base{
					accessVector:          "L",
					accessComplexity:      "H",
					authentication:        "N",
					confidentialityImpact: "C",
					integrityImpact:       "C",
					availabilityImpact:    "C",
				},
				temporal: temporal{
					exploitability:   "POC",
					remediationLevel: "OF",
					reportConfidence: "C",
				},
				environmental: environmental{
					collateralDamagePotential:  "ND",
					targetDistribution:         "ND",
					confidentialityRequirement: "ND",
					integrityRequirement:       "ND",
					availabilityRequirement:    "ND",
				},
			},
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
