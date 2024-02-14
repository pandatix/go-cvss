package differential_test

import (
	"testing"

	bunji2 "github.com/bunji2/cvssv3"
	facebook3 "github.com/facebookincubator/nvdtools/cvss3"
	goark3 "github.com/goark/go-cvss/v3/metric"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	claircore "github.com/quay/claircore/toolkit/types/cvss"
)

func v3corpus(f *testing.F) {
	f.Add("AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
	f.Add("AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
	f.Add("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
	f.Add("AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H")
	f.Add("I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:N/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U")
	f.Add("AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
}

func FuzzDifferential_V3_Bunji2(f *testing.F) {
	v3corpus(f)

	// Focus on CVSS v3.0 as bunji2 don't implement v3.1
	f.Fuzz(func(t *testing.T, raw string) {
		raw = "CVSS:3.0/" + raw
		vec1, err1 := gocvss30.ParseVector(raw)
		vec2, err2 := bunji2.ParseVector(raw)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/bunji2/cvssv3 \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		// Does not compare strict same output as CVSS v3 is laxist

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		bs2, ts2, es2 := vec2.BaseScore(), vec2.TemporalScore(), vec2.EnvironmentalScore()
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/bunji2/cvssv3 %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V3_Goark(f *testing.F) {
	v3corpus(f)

	// Focus on CVSS v3.1 as it is the last version, and as goark does both at once
	f.Fuzz(func(t *testing.T, raw string) {
		raw = "CVSS:3.1/" + raw
		vec1, err1 := gocvss31.ParseVector(raw)
		vec2, err2 := goark3.NewEnvironmental().Decode(raw)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/goark/go-cvss \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		// Does not compare strict same output as CVSS v3 is laxist

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		bs2, ts2, es2 := vec2.Base.Score(), vec2.Temporal.Score(), vec2.Score()
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/goark/go-cvss %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V3_Facebookincubator(f *testing.F) {
	v3corpus(f)

	// Focus on CVSS v3.1 as it is the last version, and as facebookincubator does both at once
	f.Fuzz(func(t *testing.T, raw string) {
		raw = "CVSS:3.1/" + raw
		vec1, err1 := gocvss31.ParseVector(raw)
		vec2, err2 := facebook3.VectorFromString(raw)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/facebookincubator/nvdtools \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		// Does not compare strict same output as CVSS v3 is laxist

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		bs2, ts2, es2 := vec2.BaseScore(), vec2.TemporalScore(), vec2.EnvironmentalScore()
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/facebookincubator/nvdtools %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V3_Claircore(f *testing.F) {
	v3corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss31.ParseVector(raw)
		vec2, err2 := claircore.ParseV3(raw)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/quay/claircore/toolkit \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		// Does not compare strict same output as CVSS v3 is laxist

		// quay/claircore is limited to environmental metrics first, which is not desirable
		es1 := vec1.EnvironmentalScore()
		es2 := vec2.Score()
		if es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave environmental score %.1f and github.com/quay/claircore/toolkit %.1f", raw, es1, es2)
		}
	})
}
