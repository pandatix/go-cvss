package gocvss40

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_SeverityDistance(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Vector          *CVSS40
		Partial         string
		ExpectedSevDist float64
	}{
		"Section 8.2": {
			// The only part documented is "VC:H/VI:H/VA:H", but to fit the internals
			// it is included in a whole valide CVSS v4.0 vector.
			Vector:          mustParse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
			Partial:         "VC:H/VI:L/VA:N",
			ExpectedSevDist: 3,
		},
		"eq3-level1-ur/ld": {
			Vector:          mustParse("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:N/VA:H/SC:H/SI:H/SA:H"),
			Partial:         "VC:N/VI:H/VA:N",
			ExpectedSevDist: 6,
		},
		"eq4-level2": {
			Vector:          mustParse("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:H/SA:H/MSI:N/MSA:N"), // SC:L/SI:N/SA:N
			Partial:         "SC:N/SI:L/SA:L",                                                                         // SC:N/SI:L/SA:L
			ExpectedSevDist: 3,
		},
		"bug-1": {
			Vector:          mustParse("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L"),
			Partial:         "AV:P/PR:N/UI:N",
			ExpectedSevDist: 3,
		},
		"bug-2": {
			Vector:          mustParse("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAT:P/MPR:N/MVI:H/MVA:N/MSI:H/MSA:N/S:N/V:C/U:Amber"),
			Partial:         "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M",
			ExpectedSevDist: 8,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			dst := severityDistance(tt.Vector, tt.Partial)

			assert.Equal(tt.ExpectedSevDist, dst)
		})
	}
}
