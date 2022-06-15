package gocvss31_test

import (
	"testing"

	gocvss31 "github.com/pandatix/go-cvss/31"
)

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss31, err := gocvss31.ParseVector(vector)

		if err != nil {
			if cvss31 != nil {
				t.Fatal("not supposed to get a CVSS31 when en error is returned")
			}
		}
	})
}
