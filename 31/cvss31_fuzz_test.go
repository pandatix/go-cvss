package gocvss31_test

import (
	"reflect"
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
		} else {
			// Check CVSS v3.1 headers
			cvss31vector := cvss31.Vector()
			if vector[:len("CVSS:3.1")] != "CVSS:3.1" {
				t.Fatalf("invalid CVSS v3.1 header of %s", vector)
			}
			if cvss31vector[:len("CVSS:3.1")] != "CVSS:3.1" {
				t.Fatalf("invalid CVSS v3.1 header of %s", cvss31vector)
			}
			// Check the cvss31's vector gives as much info as input vector
			newCVSS31, err := gocvss31.ParseVector(cvss31vector)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cvss31, newCVSS31) {
				t.Fatalf("cvss31's vector %s does not give as much info as input vector %s", cvss31vector, vector)
			}
		}
	})
}
