package gocvss30

import (
	"reflect"
	"testing"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS30 *CVSS30
	ExpectedErr    error
}{
	"CVE-2021-4131": {
		Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
		ExpectedCVSS30: &CVSS30{
			u0: 0b00000101,
			u1: 0b00010000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVE-2020-2931": {
		Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS30: &CVSS30{
			u0: 0b00000000,
			u1: 0b00000000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"all-defined": {
		Vector: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
		ExpectedCVSS30: &CVSS30{
			u0: 0b00101000,
			u1: 0b00101001,
			u2: 0b10001010,
			u3: 0b10100101,
			u4: 0b01011001,
			u5: 0b01010000,
		},
		ExpectedErr: nil,
	},
	"whatever-order": {
		Vector: "CVSS:3.0/I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:A/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U",
		ExpectedCVSS30: &CVSS30{
			u0: 0b01101000,
			u1: 0b00101001,
			u2: 0b10001010,
			u3: 0b10100101,
			u4: 0b01011001,
			u5: 0b01010000,
		},
		ExpectedErr: nil,
	},
	"invalid-header": {
		Vector:         "Something that does not start with CVSS:3.0",
		ExpectedCVSS30: nil,
		ExpectedErr:    ErrInvalidCVSSHeader,
	},
	"invalid-metric-value": {
		Vector:         "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:InVaLiD/C:N/I:H/A:N",
		ExpectedCVSS30: nil,
		ExpectedErr:    ErrInvalidMetricValue,
	},
}

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss30, err := ParseVector(vector)

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
			newCVSS30, err := ParseVector(cvss30vector)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cvss30, newCVSS30) {
				t.Fatalf("cvss30's vector %s does not give as much info as input vector %s", cvss30vector, vector)
			}
		}
	})
}
