package gocvss31

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS31 *CVSS31
	ExpectedErr    error
}{
	"CVE-2021-28378": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       "N",
				attackComplexity:   "L",
				privilegesRequired: "L",
				userInteraction:    "R",
				scope:              "C",
				confidentiality:    "L",
				integrity:          "L",
				availability:       "N",
			},
			temporal: temporal{
				exploitCodeMaturity: "X",
				remediationLevel:    "X",
				reportConfidence:    "X",
			},
			environmental: environmental{
				confidentialityRequirement: "X",
				integrityRequirement:       "X",
				availabilityRequirement:    "X",
				modifiedAttackVector:       "X",
				modifiedAttackComplexity:   "X",
				modifiedPrivilegesRequired: "X",
				modifiedUserInteraction:    "X",
				modifiedScope:              "X",
				modifiedConfidentiality:    "X",
				modifiedIntegrity:          "X",
				modifiedAvailability:       "X",
			},
		},
		ExpectedErr: nil,
	},
	"CVE-2020-14144": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       "N",
				attackComplexity:   "L",
				privilegesRequired: "H",
				userInteraction:    "N",
				scope:              "U",
				confidentiality:    "H",
				integrity:          "H",
				availability:       "H",
			},
			temporal: temporal{
				exploitCodeMaturity: "X",
				remediationLevel:    "X",
				reportConfidence:    "X",
			},
			environmental: environmental{
				confidentialityRequirement: "X",
				integrityRequirement:       "X",
				availabilityRequirement:    "X",
				modifiedAttackVector:       "X",
				modifiedAttackComplexity:   "X",
				modifiedPrivilegesRequired: "X",
				modifiedUserInteraction:    "X",
				modifiedScope:              "X",
				modifiedConfidentiality:    "X",
				modifiedIntegrity:          "X",
				modifiedAvailability:       "X",
			},
		},
		ExpectedErr: nil,
	},
	"CVE-2021-44228": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       "N",
				attackComplexity:   "L",
				privilegesRequired: "N",
				userInteraction:    "N",
				scope:              "C",
				confidentiality:    "H",
				integrity:          "H",
				availability:       "H",
			},
			temporal: temporal{
				exploitCodeMaturity: "X",
				remediationLevel:    "X",
				reportConfidence:    "X",
			},
			environmental: environmental{
				confidentialityRequirement: "X",
				integrityRequirement:       "X",
				availabilityRequirement:    "X",
				modifiedAttackVector:       "X",
				modifiedAttackComplexity:   "X",
				modifiedPrivilegesRequired: "X",
				modifiedUserInteraction:    "X",
				modifiedScope:              "X",
				modifiedConfidentiality:    "X",
				modifiedIntegrity:          "X",
				modifiedAvailability:       "X",
			},
		},
	},
	"Fuzz 548eabe03ebb3d1fdc8956e28ea60a898abedb09994812af4c3ccf8cfcc2e490": {
		// This fuzz crasher shows that the parser did not validate
		// the CVSS header.
		Vector:         "000003.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		ExpectedCVSS31: nil,
		ExpectedErr:    ErrInvalidCVSSHeader,
	},
}

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss31, err := ParseVector(tt.Vector)

			assert.Equal(tt.ExpectedCVSS31, cvss31)
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
		"CVE-2021-28378": {
			Score:          5.4,
			ExpectedRating: "MEDIUM",
			ExpectedErr:    nil,
		},
		"CVE-2020-14144": {
			Score:          7.2,
			ExpectedRating: "HIGH",
			ExpectedErr:    nil,
		},
		"CVE-2021-44228": {
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

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS31                     *CVSS31
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVE-2021-28378": {
			CVSS31: &CVSS31{
				base: base{
					attackVector:       "N",
					attackComplexity:   "L",
					privilegesRequired: "L",
					userInteraction:    "R",
					scope:              "C",
					confidentiality:    "L",
					integrity:          "L",
					availability:       "N",
				},
				temporal: temporal{
					exploitCodeMaturity: "X",
					remediationLevel:    "X",
					reportConfidence:    "X",
				},
				environmental: environmental{
					confidentialityRequirement: "X",
					integrityRequirement:       "X",
					availabilityRequirement:    "X",
					modifiedAttackVector:       "X",
					modifiedAttackComplexity:   "X",
					modifiedPrivilegesRequired: "X",
					modifiedUserInteraction:    "X",
					modifiedScope:              "X",
					modifiedConfidentiality:    "X",
					modifiedIntegrity:          "X",
					modifiedAvailability:       "X",
				},
			},
			ExpectedBaseScore:          5.4,
			ExpectedTemporalScore:      5.4,
			ExpectedEnvironmentalScore: 5.4,
		},
		"CVE-2020-14144": {
			CVSS31: &CVSS31{
				base: base{
					attackVector:       "N",
					attackComplexity:   "L",
					privilegesRequired: "H",
					userInteraction:    "N",
					scope:              "U",
					confidentiality:    "H",
					integrity:          "H",
					availability:       "H",
				},
				temporal: temporal{
					exploitCodeMaturity: "X",
					remediationLevel:    "X",
					reportConfidence:    "X",
				},
				environmental: environmental{
					confidentialityRequirement: "X",
					integrityRequirement:       "X",
					availabilityRequirement:    "X",
					modifiedAttackVector:       "X",
					modifiedAttackComplexity:   "X",
					modifiedPrivilegesRequired: "X",
					modifiedUserInteraction:    "X",
					modifiedScope:              "X",
					modifiedConfidentiality:    "X",
					modifiedIntegrity:          "X",
					modifiedAvailability:       "X",
				},
			},
			ExpectedBaseScore:          7.2,
			ExpectedTemporalScore:      7.2,
			ExpectedEnvironmentalScore: 7.2,
		},
		"CVE-2021-44228": {
			CVSS31: &CVSS31{
				base: base{
					attackVector:       "N",
					attackComplexity:   "L",
					privilegesRequired: "N",
					userInteraction:    "N",
					scope:              "C",
					confidentiality:    "H",
					integrity:          "H",
					availability:       "H",
				},
				temporal: temporal{
					exploitCodeMaturity: "X",
					remediationLevel:    "X",
					reportConfidence:    "X",
				},
				environmental: environmental{
					confidentialityRequirement: "X",
					integrityRequirement:       "X",
					availabilityRequirement:    "X",
					modifiedAttackVector:       "X",
					modifiedAttackComplexity:   "X",
					modifiedPrivilegesRequired: "X",
					modifiedUserInteraction:    "X",
					modifiedScope:              "X",
					modifiedConfidentiality:    "X",
					modifiedIntegrity:          "X",
					modifiedAvailability:       "X",
				},
			},
			ExpectedBaseScore:          10.0,
			ExpectedTemporalScore:      10.0,
			ExpectedEnvironmentalScore: 10.0,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			baseScore := tt.CVSS31.BaseScore()
			temporalScore := tt.CVSS31.TemporalScore()
			environmentalScore := tt.CVSS31.EnvironmentalScore()

			assert.Equal(tt.ExpectedBaseScore, baseScore)
			assert.Equal(tt.ExpectedTemporalScore, temporalScore)
			assert.Equal(tt.ExpectedEnvironmentalScore, environmentalScore)
		})
	}
}
