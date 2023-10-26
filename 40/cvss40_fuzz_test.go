package gocvss40

import (
	"reflect"
	"regexp"
	"testing"
)

var (
	metricRegex = map[string]string{
		// Base
		"AV": "(\\/AV:[NALP])",
		"AC": "(\\/AC:[LH])",
		"AT": "(\\/AT:[NP])",
		"PR": "(\\/PR:[NLH])",
		"UI": "(\\/UI:[NPA])",
		"VC": "(\\/VC:[HLN])",
		"VI": "(\\/VI:[HLN])",
		"VA": "(\\/VA:[HLN])",
		"SC": "(\\/SC:[HLN])",
		"SI": "(\\/SI:[HLN])",
		"SA": "(\\/SA:[HLN])",
		// Threat
		"E": "(\\/E:[XAPU])?",
		// Environmental
		"CR":  "(\\/CR:[XHML])?",
		"IR":  "(\\/IR:[XHML])?",
		"AR":  "(\\/AR:[XHML])?",
		"MAV": "(\\/MAV:[XNALP])?",
		"MAC": "(\\/MAC:[XLH])?",
		"MAT": "(\\/MAT:[XNP])?",
		"MPR": "(\\/MPR:[XNLH])?",
		"MUI": "(\\/MUI:[XNPA])?",
		"MVC": "(\\/MVC:[XNLH])?",
		"MVI": "(\\/MVI:[XNLH])?",
		"MVA": "(\\/MVA:[XNLH])?",
		"MSC": "(\\/MSC:[XNLH])?",
		"MSI": "(\\/MSI:[XNLHS])?",
		"MSA": "(\\/MSA:[XNLHS])?",
		// Supplemental
		"S":  "(\\/S:[XNP])?",
		"AU": "(\\/AU:[XNY])?",
		"R":  "(\\/R:[XAUI])?",
		"V":  "(\\/V:[XDC])?",
		"RE": "(\\/RE:[XLMH])?",
		"U":  "(\\/U:(?:X|Clear|Green|Amber|Red))?",
	}
)

func FuzzParseVector(f *testing.F) {
	rgx := "CVSS:4[.]0"
	for _, group := range order {
		for _, metric := range group {
			rgx += metricRegex[metric]
		}
	}
	rgx = "^" + rgx + "$"
	regex := regexp.MustCompile(rgx)

	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss40, err := ParseVector(vector)
		match := regex.Match([]byte(vector))

		if (err != nil) == match {
			t.Fatalf("vector %s is %t according to the regex but got error %v", vector, match, err)
		}
		if err != nil {
			if cvss40 != nil {
				t.Fatal("not supposed to get a CVSS40 when en error is returned")
			}
			return
		}

		// Compute score
		score := cvss40.Score()
		if score < 0.0 || score > 10.0 {
			t.Fatalf("score is out of bounds: %.1f", score)
		}

		// Ensure produced string vector is valid
		cvss40vector := cvss40.Vector()
		newCVSS40, _ := ParseVector(cvss40vector)
		if !reflect.DeepEqual(cvss40, newCVSS40) {
			t.Fatalf("cvss40's vector %s does not give as much info as input vector %s", cvss40vector, vector)
		}
	})
}
