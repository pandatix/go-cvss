package gocvss30_test

import (
	"reflect"
	"testing"

	gocvss30 "github.com/pandatix/go-cvss/30"
)

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss30, err := gocvss30.ParseVector(vector)

		if err != nil {
			if cvss30 != nil {
				t.Fatal("not supposed to get a CVSS30 when en error is returned")
			}
		} else {
			// Check CVSS v3.0 headers
			cvss30vector := cvss30.Vector()
			if vector[:len("CVSS:3.0")] != "CVSS:3.0" {
				t.Fatalf("invalid CVSS v3.0 header of %s", vector)
			}
			if cvss30vector[:len("CVSS:3.0")] != "CVSS:3.0" {
				t.Fatalf("invalid CVSS v3.0 header of %s", cvss30vector)
			}
			// Check the cvss30's vector gives as much info as input vector
			newCVSS30, err := gocvss30.ParseVector(cvss30vector)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cvss30, newCVSS30) {
				t.Fatalf("cvss30's vector %s does not give as much info as input vector %s", cvss30vector, vector)
			}
		}
	})
}
