package gocvss20_test

import (
	"testing"

	gocvss20 "github.com/pandatix/go-cvss/20"
	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS20 *gocvss20.CVSS20
	ExpectedErr    error
}{
	"CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392": {
		Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &gocvss20.CVSS20{
			Base: gocvss20.Base{
				AccessVector:          "N",
				AccessComplexity:      "L",
				Authentication:        "N",
				ConfidentialityImpact: "N",
				IntegrityImpact:       "N",
				AvailabilityImpact:    "C",
			},
			Temporal: gocvss20.Temporal{
				Exploitability:   "F",
				RemediationLevel: "OF",
				ReportConfidence: "C",
			},
			Environmental: gocvss20.Environmental{
				CollateralDamagePotential:  "ND",
				TargetDistribution:         "ND",
				ConfidentialityRequirement: "ND",
				IntegrityRequirement:       "ND",
				AvailabilityRequirement:    "ND",
			},
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
		Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &gocvss20.CVSS20{
			Base: gocvss20.Base{
				AccessVector:          "N",
				AccessComplexity:      "L",
				Authentication:        "N",
				ConfidentialityImpact: "C",
				IntegrityImpact:       "C",
				AvailabilityImpact:    "C",
			},
			Temporal: gocvss20.Temporal{
				Exploitability:   "F",
				RemediationLevel: "OF",
				ReportConfidence: "C",
			},
			Environmental: gocvss20.Environmental{
				CollateralDamagePotential:  "ND",
				TargetDistribution:         "ND",
				ConfidentialityRequirement: "ND",
				IntegrityRequirement:       "ND",
				AvailabilityRequirement:    "ND",
			},
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
		Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
		ExpectedCVSS20: &gocvss20.CVSS20{
			Base: gocvss20.Base{
				AccessVector:          "L",
				AccessComplexity:      "H",
				Authentication:        "N",
				ConfidentialityImpact: "C",
				IntegrityImpact:       "C",
				AvailabilityImpact:    "C",
			},
			Temporal: gocvss20.Temporal{
				Exploitability:   "POC",
				RemediationLevel: "OF",
				ReportConfidence: "C",
			},
			Environmental: gocvss20.Environmental{
				CollateralDamagePotential:  "ND",
				TargetDistribution:         "ND",
				ConfidentialityRequirement: "ND",
				IntegrityRequirement:       "ND",
				AvailabilityRequirement:    "ND",
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

			cvss20, err := gocvss20.ParseVector(tt.Vector)

			assert.Equal(tt.ExpectedCVSS20, cvss20)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS20                     *gocvss20.CVSS20
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392": {
			CVSS20: &gocvss20.CVSS20{
				Base: gocvss20.Base{
					AccessVector:          "N",
					AccessComplexity:      "L",
					Authentication:        "N",
					ConfidentialityImpact: "N",
					IntegrityImpact:       "N",
					AvailabilityImpact:    "C",
				},
				Temporal: gocvss20.Temporal{
					Exploitability:   "F",
					RemediationLevel: "OF",
					ReportConfidence: "C",
				},
				Environmental: gocvss20.Environmental{
					CollateralDamagePotential:  "ND",
					TargetDistribution:         "ND",
					ConfidentialityRequirement: "ND",
					IntegrityRequirement:       "ND",
					AvailabilityRequirement:    "ND",
				},
			},
			ExpectedBaseScore:          7.8,
			ExpectedTemporalScore:      6.4,
			ExpectedEnvironmentalScore: 6.4,
		},
		"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
			CVSS20: &gocvss20.CVSS20{
				Base: gocvss20.Base{
					AccessVector:          "N",
					AccessComplexity:      "L",
					Authentication:        "N",
					ConfidentialityImpact: "C",
					IntegrityImpact:       "C",
					AvailabilityImpact:    "C",
				},
				Temporal: gocvss20.Temporal{
					Exploitability:   "F",
					RemediationLevel: "OF",
					ReportConfidence: "C",
				},
				Environmental: gocvss20.Environmental{
					CollateralDamagePotential:  "ND",
					TargetDistribution:         "ND",
					ConfidentialityRequirement: "ND",
					IntegrityRequirement:       "ND",
					AvailabilityRequirement:    "ND",
				},
			},
			ExpectedBaseScore:          10.0,
			ExpectedTemporalScore:      8.3,
			ExpectedEnvironmentalScore: 8.3,
		},
		"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
			CVSS20: &gocvss20.CVSS20{
				Base: gocvss20.Base{
					AccessVector:          "L",
					AccessComplexity:      "H",
					Authentication:        "N",
					ConfidentialityImpact: "C",
					IntegrityImpact:       "C",
					AvailabilityImpact:    "C",
				},
				Temporal: gocvss20.Temporal{
					Exploitability:   "POC",
					RemediationLevel: "OF",
					ReportConfidence: "C",
				},
				Environmental: gocvss20.Environmental{
					CollateralDamagePotential:  "ND",
					TargetDistribution:         "ND",
					ConfidentialityRequirement: "ND",
					IntegrityRequirement:       "ND",
					AvailabilityRequirement:    "ND",
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
