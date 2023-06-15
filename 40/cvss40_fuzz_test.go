package gocvss40

import (
	"reflect"
	"testing"
)

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss40, err := ParseVector(vector)

		if err != nil {
			if cvss40 != nil {
				t.Fatal("not supposed to get a CVSS40 when en error is returned")
			}
			return
		}

		// Compute score
		// cvss40.Score()

		// Check CVSS v4.0 headers
		cvss40vector := cvss40.Vector()
		if vector[:len("CVSS:4.0")] != "CVSS:4.0" {
			t.Fatalf("invalid CVSS v4.0 header of %s", vector)
		}
		if cvss40vector[:len("CVSS:4.0")] != "CVSS:4.0" {
			t.Fatalf("invalid CVSS v4.0 header of %s", cvss40vector)
		}

		// Check the cvss40's vector gives as much info as input vector
		newCVSS40, err := ParseVector(cvss40vector)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cvss40, newCVSS40) {
			t.Fatalf("cvss40's vector %s does not give as much info as input vector %s", cvss40vector, vector)
		}
	})
}
