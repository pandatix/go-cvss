package differential_test

import (
	"testing"

	attwad "github.com/attwad/gocvss"
	facebook2 "github.com/facebookincubator/nvdtools/cvss2"
	goark2 "github.com/goark/go-cvss/v2/metric"
	gocvss20 "github.com/pandatix/go-cvss/20"
	claircore "github.com/quay/claircore/toolkit/types/cvss"
	umisama "github.com/umisama/go-cvss"
	zntrio "github.com/zntrio/mitre/cvss/v2/vector"
)

func v2corpus(f *testing.F) {
	f.Add("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C")
	f.Add("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C")
	f.Add("AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C")
	f.Add("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	f.Add("AV:L/AC:M/Au:S/C:N/I:N/A:P/CDP:N/TD:ND/CR:M/IR:ND/AR:ND")
	f.Add("AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H")
	f.Add("AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:ND/AR:ND")
	f.Add("//////////////")
	f.Add("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
}

func FuzzDifferential_V2_Goark(f *testing.F) {
	v2corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss20.ParseVector(raw)
		vec2, err2 := goark2.NewEnvironmental().Decode(raw)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/goark/go-cvss \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		outVec1 := vec1.Vector()
		outVec2 := vec2.String()
		if outVec1 != outVec2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss vectorized %s and github.com/goark/go-cvss %s", raw, outVec1, outVec2)
		}

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		bs2, ts2, es2 := vec2.BaseMetrics().Score(), vec2.Temporal.Score(), vec2.Score()
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/goark/go-cvss %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V2_Facebookincubator(f *testing.F) {
	v2corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss20.ParseVector(raw)
		vec2, err2 := facebook2.VectorFromString(raw)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/facebookincubator/nvdtools/cvss3 \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		outVec1 := vec1.Vector()
		outVec2 := vec2.String()
		if outVec1 != outVec2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss vectorized %s and github.com/facebookincubator/nvdtools/cvss3 %s", raw, outVec1, outVec2)
		}

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		bs2, ts2, es2 := vec2.Score(), vec2.TemporalScore(), vec2.EnvironmentalScore()
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/facebookincubator/nvdtools/cvss3 %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V2_Zntrio(f *testing.F) {
	v2corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss20.ParseVector(raw)
		vec2, err2 := zntrio.FromString(raw)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/zntrio/mitre/mitre \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		outVec1 := vec1.Vector()
		outVec2, err := zntrio.ToString(vec2)
		if err != nil {
			t.Fatalf("For vector %s, github.com/zntrio/mitre/mitre raised error \"%s\" when vectorizing", raw, err)
		}
		if outVec1 != outVec2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss vectorized %s and github.com/zntrio/mitre/mitre %s", raw, outVec1, outVec2)
		}

		// github.com/zntrio/mitre does not handle CVSS v2 scoring
	})
}

func FuzzDifferential_V2_Attwad(f *testing.F) {
	v2corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss20.ParseVector(raw)
		vec2, err2 := attwad.Parse(raw)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/attwad/gocvss \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		outVec1 := vec1.Vector()
		outVec2 := vec2.ToStringVector()
		if outVec1 != outVec2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss vectorized %s and github.com/attwad/gocvss %s", raw, outVec1, outVec2)
		}

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		s2 := vec2.Score()
		bs2, ts2, es2 := s2.Base, s2.Temporal, s2.Environmental
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/attwad/gocvss %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V2_Umisama(f *testing.F) {
	v2corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss20.ParseVector(raw)
		vec2, err2 := umisama.ParseVectors(raw)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss raised error \"%v\" and github.com/umisama/go-cvss \"%v\"", raw, err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}

		outVec1 := vec1.Vector()
		outVec2 := vec2.String()
		if outVec1 != outVec2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss vectorized %s and github.com/umisama/go-cvss %s", raw, outVec1, outVec2)
		}

		bs1, ts1, es1 := vec1.BaseScore(), vec1.TemporalScore(), vec1.EnvironmentalScore()
		bs2, ts2, es2 := vec2.BaseScore(), vec2.TemporalScore(), vec2.EnvironmentalScore()
		if bs1 != bs2 || ts1 != ts2 || es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave scores %.1f;%.1f;%.1f and github.com/umisama/go-cvss %.1f;%.1f;%.1f", raw, bs1, ts1, es1, bs2, ts2, es2)
		}
	})
}

func FuzzDifferential_V2_Claircore(f *testing.F) {
	v2corpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		vec1, err1 := gocvss20.ParseVector(raw)
		vec2, err2 := claircore.ParseV2(raw)

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

		// quay/claircore is limited to environmental metrics first, which is not desirable
		es1 := vec1.EnvironmentalScore()
		es2 := vec2.Score()
		if es1 != es2 {
			t.Fatalf("For vector %s, github.com/pandatix/go-cvss gave environmental score %.1f and github.com/quay/claircore/toolkit %.1f", raw, es1, es2)
		}
	})
}
