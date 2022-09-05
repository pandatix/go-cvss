package gocvss31_test

import (
	"testing"

	gocvss31 "github.com/pandatix/go-cvss/31"
	"github.com/stretchr/testify/assert"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS31 *gocvss31.CVSS31
	ExpectedErr    error
}{
	"CVE-2021-28378": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		ExpectedCVSS31: &gocvss31.CVSS31{
			Base: gocvss31.Base{
				AttackVector:       "N",
				AttackComplexity:   "L",
				PrivilegesRequired: "L",
				UserInteraction:    "R",
				Scope:              "C",
				Confidentiality:    "L",
				Integrity:          "L",
				Availability:       "N",
			},
			Temporal: gocvss31.Temporal{
				ExploitCodeMaturity: "X",
				RemediationLevel:    "X",
				ReportConfidence:    "X",
			},
			Environmental: gocvss31.Environmental{
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
	"CVE-2020-14144": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS31: &gocvss31.CVSS31{
			Base: gocvss31.Base{
				AttackVector:       "N",
				AttackComplexity:   "L",
				PrivilegesRequired: "H",
				UserInteraction:    "N",
				Scope:              "U",
				Confidentiality:    "H",
				Integrity:          "H",
				Availability:       "H",
			},
			Temporal: gocvss31.Temporal{
				ExploitCodeMaturity: "X",
				RemediationLevel:    "X",
				ReportConfidence:    "X",
			},
			Environmental: gocvss31.Environmental{
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
	"CVE-2021-44228": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		ExpectedCVSS31: &gocvss31.CVSS31{
			Base: gocvss31.Base{
				AttackVector:       "N",
				AttackComplexity:   "L",
				PrivilegesRequired: "N",
				UserInteraction:    "N",
				Scope:              "C",
				Confidentiality:    "H",
				Integrity:          "H",
				Availability:       "H",
			},
			Temporal: gocvss31.Temporal{
				ExploitCodeMaturity: "X",
				RemediationLevel:    "X",
				ReportConfidence:    "X",
			},
			Environmental: gocvss31.Environmental{
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
	},
	"Fuzz 548eabe03ebb3d1fdc8956e28ea60a898abedb09994812af4c3ccf8cfcc2e490": {
		// This fuzz crasher shows that the parser did not validate
		// the CVSS header.
		Vector:         "000003.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		ExpectedCVSS31: nil,
		ExpectedErr:    gocvss31.ErrInvalidCVSSHeader,
	},
}

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss31, err := gocvss31.ParseVector(tt.Vector)

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

			rating, err := gocvss31.Rating(tt.Score)

			assert.Equal(tt.ExpectedRating, rating)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestScores(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS31                     *gocvss31.CVSS31
		ExpectedBaseScore          float64
		ExpectedTemporalScore      float64
		ExpectedEnvironmentalScore float64
	}{
		"CVE-2021-28378": {
			CVSS31: &gocvss31.CVSS31{
				Base: gocvss31.Base{
					AttackVector:       "N",
					AttackComplexity:   "L",
					PrivilegesRequired: "L",
					UserInteraction:    "R",
					Scope:              "C",
					Confidentiality:    "L",
					Integrity:          "L",
					Availability:       "N",
				},
				Temporal: gocvss31.Temporal{
					ExploitCodeMaturity: "X",
					RemediationLevel:    "X",
					ReportConfidence:    "X",
				},
				Environmental: gocvss31.Environmental{
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
			ExpectedBaseScore:          5.4,
			ExpectedTemporalScore:      5.4,
			ExpectedEnvironmentalScore: 5.4,
		},
		"CVE-2020-14144": {
			CVSS31: &gocvss31.CVSS31{
				Base: gocvss31.Base{
					AttackVector:       "N",
					AttackComplexity:   "L",
					PrivilegesRequired: "H",
					UserInteraction:    "N",
					Scope:              "U",
					Confidentiality:    "H",
					Integrity:          "H",
					Availability:       "H",
				},
				Temporal: gocvss31.Temporal{
					ExploitCodeMaturity: "X",
					RemediationLevel:    "X",
					ReportConfidence:    "X",
				},
				Environmental: gocvss31.Environmental{
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
			ExpectedBaseScore:          7.2,
			ExpectedTemporalScore:      7.2,
			ExpectedEnvironmentalScore: 7.2,
		},
		"CVE-2021-44228": {
			CVSS31: &gocvss31.CVSS31{
				Base: gocvss31.Base{
					AttackVector:       "N",
					AttackComplexity:   "L",
					PrivilegesRequired: "N",
					UserInteraction:    "N",
					Scope:              "C",
					Confidentiality:    "H",
					Integrity:          "H",
					Availability:       "H",
				},
				Temporal: gocvss31.Temporal{
					ExploitCodeMaturity: "X",
					RemediationLevel:    "X",
					ReportConfidence:    "X",
				},
				Environmental: gocvss31.Environmental{
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

var Gcvss31 *gocvss31.CVSS31
var Gerr error

func BenchmarkParseVector_Base(b *testing.B) {
	benchmarkParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", b)
}

func BenchmarkParseVector_WithTempAndEnv(b *testing.B) {
	benchmarkParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RL:O/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H", b)
}

func benchmarkParseVector(vector string, b *testing.B) {
	var cvss31 *gocvss31.CVSS31
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cvss31, err = gocvss31.ParseVector(vector)
	}
	Gcvss31 = cvss31
	Gerr = err
}

var Gstr string

func BenchmarkCVSS31Vector(b *testing.B) {
	cvss31 := &gocvss31.CVSS31{
		Base: gocvss31.Base{
			AttackVector:       "N",
			AttackComplexity:   "L",
			PrivilegesRequired: "L",
			UserInteraction:    "R",
			Scope:              "C",
			Confidentiality:    "L",
			Integrity:          "L",
			Availability:       "N",
		},
		Temporal: gocvss31.Temporal{
			ExploitCodeMaturity: "U",
			RemediationLevel:    "X",
			ReportConfidence:    "C",
		},
		Environmental: gocvss31.Environmental{
			ConfidentialityRequirement: "H",
			IntegrityRequirement:       "M",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "R",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "H",
			ModifiedIntegrity:          "H",
			ModifiedAvailability:       "H",
		},
	}
	var str string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str = cvss31.Vector()
	}
	Gstr = str
}

var Gget string

func BenchmarkCVSS31Get(b *testing.B) {
	const abv = "UI"
	cvss31 := &gocvss31.CVSS31{
		Base: gocvss31.Base{
			AttackVector:       "N",
			AttackComplexity:   "L",
			PrivilegesRequired: "L",
			UserInteraction:    "R",
			Scope:              "C",
			Confidentiality:    "L",
			Integrity:          "L",
			Availability:       "N",
		},
		Temporal: gocvss31.Temporal{
			ExploitCodeMaturity: "U",
			RemediationLevel:    "O",
			ReportConfidence:    "C",
		},
		Environmental: gocvss31.Environmental{
			ConfidentialityRequirement: "H",
			IntegrityRequirement:       "M",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "R",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "H",
			ModifiedIntegrity:          "H",
			ModifiedAvailability:       "H",
		},
	}
	var get string
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get, err = cvss31.Get(abv)
	}
	Gget = get
	Gerr = err
}

func BenchmarkCVSS31Set(b *testing.B) {
	const abv = "UI"
	const value = "R"
	cvss31 := &gocvss31.CVSS31{
		Base: gocvss31.Base{
			AttackVector:       "N",
			AttackComplexity:   "L",
			PrivilegesRequired: "L",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:    "L",
			Integrity:          "L",
			Availability:       "N",
		},
		Temporal: gocvss31.Temporal{
			ExploitCodeMaturity: "U",
			RemediationLevel:    "O",
			ReportConfidence:    "C",
		},
		Environmental: gocvss31.Environmental{
			ConfidentialityRequirement: "H",
			IntegrityRequirement:       "M",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "R",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "H",
			ModifiedIntegrity:          "H",
			ModifiedAvailability:       "H",
		},
	}
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = cvss31.Set(abv, value)
	}
	Gerr = err
}

var Gscore float64

func BenchmarkCVSS31BaseScore(b *testing.B) {
	var score float64
	cvss31 := &gocvss31.CVSS31{
		Base: gocvss31.Base{
			AttackVector:       "N",
			AttackComplexity:   "L",
			PrivilegesRequired: "L",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:    "L",
			Integrity:          "L",
			Availability:       "N",
		},
		Temporal: gocvss31.Temporal{
			ExploitCodeMaturity: "U",
			RemediationLevel:    "O",
			ReportConfidence:    "C",
		},
		Environmental: gocvss31.Environmental{
			ConfidentialityRequirement: "H",
			IntegrityRequirement:       "M",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "R",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "H",
			ModifiedIntegrity:          "H",
			ModifiedAvailability:       "H",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss31.BaseScore()
	}
	Gscore = score
}

func BenchmarkCVSS31TemporalScore(b *testing.B) {
	var score float64
	cvss31 := &gocvss31.CVSS31{
		Base: gocvss31.Base{
			AttackVector:       "N",
			AttackComplexity:   "L",
			PrivilegesRequired: "L",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:    "L",
			Integrity:          "L",
			Availability:       "N",
		},
		Temporal: gocvss31.Temporal{
			ExploitCodeMaturity: "U",
			RemediationLevel:    "O",
			ReportConfidence:    "C",
		},
		Environmental: gocvss31.Environmental{
			ConfidentialityRequirement: "H",
			IntegrityRequirement:       "M",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "R",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "H",
			ModifiedIntegrity:          "H",
			ModifiedAvailability:       "H",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss31.TemporalScore()
	}
	Gscore = score
}

func BenchmarkCVSS31EnvironmentalScore(b *testing.B) {
	var score float64
	cvss31 := &gocvss31.CVSS31{
		Base: gocvss31.Base{
			AttackVector:       "N",
			AttackComplexity:   "L",
			PrivilegesRequired: "L",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:    "L",
			Integrity:          "L",
			Availability:       "N",
		},
		Temporal: gocvss31.Temporal{
			ExploitCodeMaturity: "U",
			RemediationLevel:    "O",
			ReportConfidence:    "C",
		},
		Environmental: gocvss31.Environmental{
			ConfidentialityRequirement: "H",
			IntegrityRequirement:       "M",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "R",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "H",
			ModifiedIntegrity:          "H",
			ModifiedAvailability:       "H",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss31.EnvironmentalScore()
	}
	Gscore = score
}
