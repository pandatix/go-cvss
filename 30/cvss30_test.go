package gocvss30_test

import (
	"testing"

	gocvss30 "github.com/pandatix/go-cvss/30"
	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS30 *gocvss30.CVSS30
	ExpectedErr    error
}{
	"CVE-2021-4131": {
		Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
		ExpectedCVSS30: &gocvss30.CVSS30{
			Base: gocvss30.Base{
				AttackVector:       "N",
				AttackComplexity:   "L",
				PrivilegesRequired: "N",
				UserInteraction:    "R",
				Scope:              "U",
				Confidentiality:    "N",
				Integrity:          "H",
				Availability:       "N",
			},
			Temporal: gocvss30.Temporal{
				ExploitCodeMaturity: "X",
				RemediationLevel:    "X",
				ReportConfidence:    "X",
			},
			Environmental: gocvss30.Environmental{
				ConfidentialityRequirement: "X",
				IntegrityRequirement:       "X",
				AvailabilityRequirement:    "X",
				ModifiedAttackVector:       "X",
				ModifiedAttackComplexity:   "X",
				ModifiedPrivilegesRequired: "X",
				ModifiedUserInteraction:    "X",
				ModifiedScope:              "X",
				ModifiedConfidentiality:    "X",
				ModifiedIntegrity:          "X",
				ModifiedAvailability:       "X",
			},
		},
		ExpectedErr: nil,
	},
	"CVE-2020-2931": {
		Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS30: &gocvss30.CVSS30{
			Base: gocvss30.Base{
				AttackVector:       "N",
				AttackComplexity:   "L",
				PrivilegesRequired: "N",
				UserInteraction:    "N",
				Scope:              "U",
				Confidentiality:    "H",
				Integrity:          "H",
				Availability:       "H",
			},
			Temporal: gocvss30.Temporal{
				ExploitCodeMaturity: "X",
				RemediationLevel:    "X",
				ReportConfidence:    "X",
			},
			Environmental: gocvss30.Environmental{
				ConfidentialityRequirement: "X",
				IntegrityRequirement:       "X",
				AvailabilityRequirement:    "X",
				ModifiedAttackVector:       "X",
				ModifiedAttackComplexity:   "X",
				ModifiedPrivilegesRequired: "X",
				ModifiedUserInteraction:    "X",
				ModifiedScope:              "X",
				ModifiedConfidentiality:    "X",
				ModifiedIntegrity:          "X",
				ModifiedAvailability:       "X",
			},
		},
		ExpectedErr: nil,
	},
}

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss30, err := gocvss30.ParseVector(tt.Vector)

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

			rating, err := gocvss30.Rating(tt.Score)

			assert.Equal(tt.ExpectedRating, rating)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS30                     *gocvss30.CVSS30
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVE-2021-4131": {
			CVSS30: &gocvss30.CVSS30{
				Base: gocvss30.Base{
					AttackVector:       "N",
					AttackComplexity:   "L",
					PrivilegesRequired: "N",
					UserInteraction:    "R",
					Scope:              "U",
					Confidentiality:    "N",
					Integrity:          "H",
					Availability:       "N",
				},
				Temporal: gocvss30.Temporal{
					ExploitCodeMaturity: "X",
					RemediationLevel:    "X",
					ReportConfidence:    "X",
				},
				Environmental: gocvss30.Environmental{
					ConfidentialityRequirement: "X",
					IntegrityRequirement:       "X",
					AvailabilityRequirement:    "X",
					ModifiedAttackVector:       "X",
					ModifiedAttackComplexity:   "X",
					ModifiedPrivilegesRequired: "X",
					ModifiedUserInteraction:    "X",
					ModifiedScope:              "X",
					ModifiedConfidentiality:    "X",
					ModifiedIntegrity:          "X",
					ModifiedAvailability:       "X",
				},
			},
			ExpectedBaseScore:          6.5,
			ExpectedTemporalScore:      6.5,
			ExpectedEnvironmentalScore: 6.5,
		},
		"CVE-2020-2931": {
			CVSS30: &gocvss30.CVSS30{
				Base: gocvss30.Base{
					AttackVector:       "N",
					AttackComplexity:   "L",
					PrivilegesRequired: "N",
					UserInteraction:    "N",
					Scope:              "U",
					Confidentiality:    "H",
					Integrity:          "H",
					Availability:       "H",
				},
				Temporal: gocvss30.Temporal{
					ExploitCodeMaturity: "X",
					RemediationLevel:    "X",
					ReportConfidence:    "X",
				},
				Environmental: gocvss30.Environmental{
					ConfidentialityRequirement: "X",
					IntegrityRequirement:       "X",
					AvailabilityRequirement:    "X",
					ModifiedAttackVector:       "X",
					ModifiedAttackComplexity:   "X",
					ModifiedPrivilegesRequired: "X",
					ModifiedUserInteraction:    "X",
					ModifiedScope:              "X",
					ModifiedConfidentiality:    "X",
					ModifiedIntegrity:          "X",
					ModifiedAvailability:       "X",
				},
			},
			ExpectedBaseScore:          9.8,
			ExpectedTemporalScore:      9.8,
			ExpectedEnvironmentalScore: 9.8,
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
