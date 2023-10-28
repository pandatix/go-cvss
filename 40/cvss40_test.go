package gocvss40

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVector(t *testing.T) {
	t.Parallel()

	for testname, tt := range testsParseVector {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cvss40, err := ParseVector(tt.Vector)
			if (err != nil) != tt.ExpectErr {
				t.Fatalf("Expected error: %t, got %v", tt.ExpectErr, err)
			}

			if err != nil {
				return
			}
			assert.Equal(tt.ExpectedCVSS40, cvss40)
			assert.Equal(tt.Vector, cvss40.Vector())
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
		"medium": {
			Score:          5.4,
			ExpectedRating: "MEDIUM",
			ExpectedErr:    nil,
		},
		"high": {
			Score:          7.2,
			ExpectedRating: "HIGH",
			ExpectedErr:    nil,
		},
		"critical": {
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

func TestScore(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		CVSS40               *CVSS40
		ExpectedScore        float64
		ExpectedNomenclature string
	}{
		"full-impact": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
			ExpectedScore:        10.0,
			ExpectedNomenclature: "CVSS-B",
		},
		"no-impact": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"),
			ExpectedScore:        0.0,
			ExpectedNomenclature: "CVSS-B",
		},
		"full-system-no-subsequent": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			ExpectedScore:        9.3,
			ExpectedNomenclature: "CVSS-B",
		},
		"no-system-full-subsequent": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H"),
			ExpectedScore:        7.9,
			ExpectedNomenclature: "CVSS-B",
		},
		"with-t": {
			// This one verify the "full-impact" test case, with Threat intelligence
			// information, is effectively lowered.
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U"),
			ExpectedScore:        9.1,
			ExpectedNomenclature: "CVSS-BT",
		},
		"with-e": {
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:L/MSA:S"),
			ExpectedScore:        9.8,
			ExpectedNomenclature: "CVSS-BE",
		},
		"smol": {
			// This one only has a funny name :)
			CVSS40:               mustParse("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),
			ExpectedScore:        1.0,
			ExpectedNomenclature: "CVSS-B",
		},
		// Those ones used Clement as a random source.
		// It enabled detecting multiple internal issues to this Go module
		// and a typo in the official calculator a week before publication.
		// This should be kept for regression testing.
		"clement-b": {
			CVSS40:               mustParse("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L"),
			ExpectedScore:        5.2,
			ExpectedNomenclature: "CVSS-B",
		},
		"clement-bte": {
			CVSS40:               mustParse("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAT:P/MPR:N/MVI:H/MVA:N/MSI:H/MSA:N/S:N/V:C/U:Amber"),
			ExpectedScore:        4.7,
			ExpectedNomenclature: "CVSS-BTE",
		},
		"reg-deptheq3eq6": {
			// This test ensures there is no regression on the EQ3/EQ6
			// computations, originally due to a typo.
			CVSS40:               mustParse("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L"),
			ExpectedScore:        5.8,
			ExpectedNomenclature: "CVSS-BE",
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			score := tt.CVSS40.Score()
			nom := tt.CVSS40.Nomenclature()

			assert.Equal(tt.ExpectedScore, score)
			assert.Equal(tt.ExpectedNomenclature, nom)
		})
	}
}

func mustParse(vec string) *CVSS40 {
	cvss40, err := ParseVector(vec)
	if err != nil {
		panic(err)
	}
	return cvss40
}
