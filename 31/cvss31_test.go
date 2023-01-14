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
				attackVector:       av_n,
				attackComplexity:   ac_l,
				privilegesRequired: pr_l,
				userInteraction:    ui_r,
				scope:              s_c,
				confidentiality:    cia_l,
				integrity:          cia_l,
				availability:       cia_n,
			},
			temporal: temporal{
				exploitCodeMaturity: e_x,
				remediationLevel:    rl_x,
				reportConfidence:    rc_x,
			},
			environmental: environmental{
				confidentialityRequirement: ciar_x,
				integrityRequirement:       ciar_x,
				availabilityRequirement:    ciar_x,
				modifiedAttackVector:       mav_x,
				modifiedAttackComplexity:   mac_x,
				modifiedPrivilegesRequired: mpr_x,
				modifiedUserInteraction:    mui_x,
				modifiedScope:              ms_x,
				modifiedConfidentiality:    mcia_x,
				modifiedIntegrity:          mcia_x,
				modifiedAvailability:       mcia_x,
			},
		},
		ExpectedErr: nil,
	},
	"CVE-2020-14144": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       av_n,
				attackComplexity:   ac_l,
				privilegesRequired: pr_h,
				userInteraction:    ui_n,
				scope:              s_u,
				confidentiality:    cia_h,
				integrity:          cia_h,
				availability:       cia_h,
			},
			temporal: temporal{
				exploitCodeMaturity: e_x,
				remediationLevel:    rl_x,
				reportConfidence:    rc_x,
			},
			environmental: environmental{
				confidentialityRequirement: ciar_x,
				integrityRequirement:       ciar_x,
				availabilityRequirement:    ciar_x,
				modifiedAttackVector:       mav_x,
				modifiedAttackComplexity:   mac_x,
				modifiedPrivilegesRequired: mpr_x,
				modifiedUserInteraction:    mui_x,
				modifiedScope:              ms_x,
				modifiedConfidentiality:    mcia_x,
				modifiedIntegrity:          mcia_x,
				modifiedAvailability:       mcia_x,
			},
		},
		ExpectedErr: nil,
	},
	"CVE-2021-44228": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       av_n,
				attackComplexity:   ac_l,
				privilegesRequired: pr_n,
				userInteraction:    ui_n,
				scope:              s_c,
				confidentiality:    cia_h,
				integrity:          cia_h,
				availability:       cia_h,
			},
			temporal: temporal{
				exploitCodeMaturity: e_x,
				remediationLevel:    rl_x,
				reportConfidence:    rc_x,
			},
			environmental: environmental{
				confidentialityRequirement: ciar_x,
				integrityRequirement:       ciar_x,
				availabilityRequirement:    ciar_x,
				modifiedAttackVector:       mav_x,
				modifiedAttackComplexity:   mac_x,
				modifiedPrivilegesRequired: mpr_x,
				modifiedUserInteraction:    mui_x,
				modifiedScope:              ms_x,
				modifiedConfidentiality:    mcia_x,
				modifiedIntegrity:          mcia_x,
				modifiedAvailability:       mcia_x,
			},
		},
	},
	"all-defined": {
		Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       av_n,
				attackComplexity:   ac_h,
				privilegesRequired: pr_l,
				userInteraction:    ui_n,
				scope:              s_u,
				confidentiality:    cia_h,
				integrity:          cia_l,
				availability:       cia_l,
			},
			temporal: temporal{
				exploitCodeMaturity: e_h,
				remediationLevel:    rl_o,
				reportConfidence:    rc_c,
			},
			environmental: environmental{
				confidentialityRequirement: ciar_h,
				integrityRequirement:       ciar_h,
				availabilityRequirement:    ciar_h,
				modifiedAttackVector:       mav_n,
				modifiedAttackComplexity:   mac_l,
				modifiedPrivilegesRequired: mpr_n,
				modifiedUserInteraction:    mui_n,
				modifiedScope:              ms_c,
				modifiedConfidentiality:    mcia_h,
				modifiedIntegrity:          mcia_h,
				modifiedAvailability:       mcia_h,
			},
		},
		ExpectedErr: nil,
	},
	"whatever-order": {
		Vector: "CVSS:3.1/I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:N/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U",
		ExpectedCVSS31: &CVSS31{
			base: base{
				attackVector:       av_n,
				attackComplexity:   ac_h,
				privilegesRequired: pr_l,
				userInteraction:    ui_n,
				scope:              s_u,
				confidentiality:    cia_h,
				integrity:          cia_l,
				availability:       cia_l,
			},
			temporal: temporal{
				exploitCodeMaturity: e_h,
				remediationLevel:    rl_o,
				reportConfidence:    rc_c,
			},
			environmental: environmental{
				confidentialityRequirement: ciar_h,
				integrityRequirement:       ciar_h,
				availabilityRequirement:    ciar_h,
				modifiedAttackVector:       mav_n,
				modifiedAttackComplexity:   mac_l,
				modifiedPrivilegesRequired: mpr_n,
				modifiedUserInteraction:    mui_n,
				modifiedScope:              ms_c,
				modifiedConfidentiality:    mcia_h,
				modifiedIntegrity:          mcia_h,
				modifiedAvailability:       mcia_h,
			},
		},
		ExpectedErr: nil,
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
					attackVector:       av_n,
					attackComplexity:   ac_l,
					privilegesRequired: pr_l,
					userInteraction:    ui_r,
					scope:              s_c,
					confidentiality:    cia_l,
					integrity:          cia_l,
					availability:       cia_n,
				},
				temporal: temporal{
					exploitCodeMaturity: e_x,
					remediationLevel:    rl_x,
					reportConfidence:    rc_x,
				},
				environmental: environmental{
					confidentialityRequirement: ciar_x,
					integrityRequirement:       ciar_x,
					availabilityRequirement:    ciar_x,
					modifiedAttackVector:       mav_x,
					modifiedAttackComplexity:   mac_x,
					modifiedPrivilegesRequired: mpr_x,
					modifiedUserInteraction:    mui_x,
					modifiedScope:              ms_x,
					modifiedConfidentiality:    mcia_x,
					modifiedIntegrity:          mcia_x,
					modifiedAvailability:       mcia_x,
				},
			},
			ExpectedBaseScore:          5.4,
			ExpectedTemporalScore:      5.4,
			ExpectedEnvironmentalScore: 5.4,
		},
		"CVE-2020-14144": {
			CVSS31: &CVSS31{
				base: base{
					attackVector:       av_n,
					attackComplexity:   ac_l,
					privilegesRequired: pr_h,
					userInteraction:    ui_n,
					scope:              s_u,
					confidentiality:    cia_h,
					integrity:          cia_h,
					availability:       cia_h,
				},
				temporal: temporal{
					exploitCodeMaturity: e_x,
					remediationLevel:    rl_x,
					reportConfidence:    rc_x,
				},
				environmental: environmental{
					confidentialityRequirement: ciar_x,
					integrityRequirement:       ciar_x,
					availabilityRequirement:    ciar_x,
					modifiedAttackVector:       mav_x,
					modifiedAttackComplexity:   mac_x,
					modifiedPrivilegesRequired: mpr_x,
					modifiedUserInteraction:    mui_x,
					modifiedScope:              ms_x,
					modifiedConfidentiality:    mcia_x,
					modifiedIntegrity:          mcia_x,
					modifiedAvailability:       mcia_x,
				},
			},
			ExpectedBaseScore:          7.2,
			ExpectedTemporalScore:      7.2,
			ExpectedEnvironmentalScore: 7.2,
		},
		"CVE-2021-44228": {
			CVSS31: &CVSS31{
				base: base{
					attackVector:       av_n,
					attackComplexity:   ac_l,
					privilegesRequired: pr_n,
					userInteraction:    ui_n,
					scope:              s_c,
					confidentiality:    cia_h,
					integrity:          cia_h,
					availability:       cia_h,
				},
				temporal: temporal{
					exploitCodeMaturity: e_x,
					remediationLevel:    rl_x,
					reportConfidence:    rc_x,
				},
				environmental: environmental{
					confidentialityRequirement: ciar_x,
					integrityRequirement:       ciar_x,
					availabilityRequirement:    ciar_x,
					modifiedAttackVector:       mav_x,
					modifiedAttackComplexity:   mac_x,
					modifiedPrivilegesRequired: mpr_x,
					modifiedUserInteraction:    mui_x,
					modifiedScope:              ms_x,
					modifiedConfidentiality:    mcia_x,
					modifiedIntegrity:          mcia_x,
					modifiedAvailability:       mcia_x,
				},
			},
			ExpectedBaseScore:          10.0,
			ExpectedTemporalScore:      10.0,
			ExpectedEnvironmentalScore: 10.0,
		},
		"all-defined": {
			CVSS31: &CVSS31{
				base: base{
					attackVector:       av_a,
					attackComplexity:   ac_h,
					privilegesRequired: pr_l,
					userInteraction:    ui_n,
					scope:              s_c,
					confidentiality:    cia_h,
					integrity:          cia_l,
					availability:       cia_l,
				},
				temporal: temporal{
					exploitCodeMaturity: e_f,
					remediationLevel:    rl_u,
					reportConfidence:    rc_r,
				},
				environmental: environmental{
					confidentialityRequirement: ciar_h,
					integrityRequirement:       ciar_m,
					availabilityRequirement:    ciar_l,
					modifiedAttackVector:       mav_n,
					modifiedAttackComplexity:   mac_l,
					modifiedPrivilegesRequired: mpr_n,
					modifiedUserInteraction:    mui_n,
					modifiedScope:              ms_c,
					modifiedConfidentiality:    mcia_h,
					modifiedIntegrity:          mcia_h,
					modifiedAvailability:       mcia_h,
				},
			},
			ExpectedBaseScore:          7.1,
			ExpectedTemporalScore:      6.7,
			ExpectedEnvironmentalScore: 9.4,
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
