package gocvss20_test

import (
	"testing"

	gocvss20 "github.com/pandatix/go-cvss/20"
)

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss20, err := gocvss20.ParseVector(vector)

		if err != nil {
			if cvss20 != nil {
				t.Fatal("not supposed to get a CVSS20 when an error is returned")
			}
		} else {
			// This check works because CVSS v2.0 has a predetermined order.
			cvss20vector := cvss20.Vector()
			if vector != cvss20vector {
				t.Fatalf("vector differs at export: input is %s but output is %s", vector, cvss20vector)
			}
		}
	})
}
