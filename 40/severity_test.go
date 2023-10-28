package gocvss40

import (
	"fmt"
	"strings"
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

			dst := severityDistanceRaw(tt.Vector, tt.Partial)

			assert.Equal(tt.ExpectedSevDist, dst)
		})
	}
}

func severityDistanceRaw(vec *CVSS40, partial string) float64 {
	// Split parts
	pts := map[string]uint8{}
	for _, pt := range strings.Split(partial, "/") {
		k, v, _ := strings.Cut(pt, ":")
		pts[k] = indexMetricValue(k, v)
	}

	// Compute overall distance
	dst := 0.
	for k, v := range pts {
		vecVal := indexMetricValue(k, vec.getComp(k))
		dst += abs(severityDistance(indexMetric(k), vecVal, v))
	}
	return dst
}

func indexMetric(k string) uint8 {
	switch k {
	case "AV":
		return av
	case "AC":
		return ac
	case "AT":
		return at
	case "PR":
		return pr
	case "UI":
		return ui
	case "VC":
		return vc
	case "VI":
		return vi
	case "VA":
		return va
	case "SC":
		return sc
	case "SI":
		return si
	case "SA":
		return sa
	case "E":
		return e
	case "CR":
		return cr
	case "IR":
		return ir
	case "AR":
		return ar
	}
	panic(fmt.Sprintf("invalid metric %v", k))
}

func indexMetricValue(k, v string) uint8 {
	slc := map[uint8][]string{
		av: {"N", "A", "L", "P"},
		ac: {"L", "H"},
		at: {"N", "P"},
		pr: {"N", "L", "H"},
		ui: {"N", "P", "A"},
		vc: {"H", "L", "N"},
		vi: {"H", "L", "N"},
		va: {"H", "L", "N"},
		sc: {"H", "L", "N"},
		si: {"H", "L", "N", "S"},
		sa: {"H", "L", "N", "S"},
		e:  {"X", "A", "P", "U"},
		cr: {"X", "H", "M", "L"},
		ir: {"X", "H", "M", "L"},
		ar: {"X", "H", "M", "L"},
	}[indexMetric(k)]
	for i := 0; i < len(slc); i++ {
		if slc[i] == v {
			return uint8(i)
		}
	}
	panic(fmt.Sprintf("invalid metric value %s for %s", v, k))
}

func (vec *CVSS40) getComp(k string) string {
	// If a Mxx (Environmental metrics) is set, use it
	str := vec.get("M" + k)
	if str != "" && str != "X" {
		return str
	}
	// If a xx (Base metrics) is set, use it
	str = vec.get(k)
	if str != "X" {
		return str
	}
	// Last case is defaulting values
	switch k {
	case "CR", "IR", "AR":
		return "H"
	case "E":
		return "A"
	default:
		panic("invalid metric abv " + k)
	}
}
