package differential_test

import (
	"testing"

	gocvss40 "github.com/pandatix/go-cvss/40"
	claircore "github.com/quay/claircore/toolkit/types/cvss"
)

func v4corpus(f *testing.F) {
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
	f.Add("CVSS:4.0/UI:N/AC:L/VA:N/AT:N/PR:H/VC:L/SI:N/VI:L/SC:N/AV:N/SA:N")
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/SC:N/VI:L/SI:N/VA:N/SA:N/E:A/CR:M/IR:X/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:H/MSC:H/MSI:X/MSA:S/S:N/AU:X/R:I/V:C/RE:M/U:Amber")
}

func FuzzDifferential_V4_Claircore(f *testing.F) {
	v4corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss40.ParseVector(raw)
		vec2, err2 := claircore.ParseV4(raw)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/quay/claircore/toolkit \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		outVec1 := vec1.Vector()
		outVec2 := vec2.String()
		if outVec1 != outVec2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss vectorized %s and github.com/quay/claircore/toolkit %s", raw, outVec1, outVec2)
		}

		s1 := vec1.Score()
		s2 := vec2.Score()
		if s1 != s2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave score %.1f and github.com/quay/claircore/toolkit %.1f", raw, s1, s2)
		}
	})
}
