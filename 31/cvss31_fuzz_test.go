package gocvss31

import (
	"reflect"
	"testing"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS31 *CVSS31
	ExpectedErr    error
}{
	"CVE-2021-28378": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		ExpectedCVSS31: &CVSS31{
			u0: 0b00001110,
			u1: 0b10110000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVE-2020-14144": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
		ExpectedCVSS31: &CVSS31{
			u0: 0b00010000,
			u1: 0b00000000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVE-2021-44228": {
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		ExpectedCVSS31: &CVSS31{
			u0: 0b00000010,
			u1: 0b00000000,
			u2: 0b00000000,
			u3: 0b00000000,
			u4: 0b00000000,
			u5: 0b00000000,
		},
	},
	"all-defined": {
		Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
		ExpectedCVSS31: &CVSS31{
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
		Vector: "CVSS:3.1/I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:N/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U",
		ExpectedCVSS31: &CVSS31{
			u0: 0b00101000,
			u1: 0b00101001,
			u2: 0b10001010,
			u3: 0b10100101,
			u4: 0b01011001,
			u5: 0b01010000,
		},
		ExpectedErr: nil,
	},
	"Fuzz 548eabe03ebb3d1fdc8956e28ea60a898abedb09994812af4c3ccf8cfcc2e490": {
		// This fuzz crasher shows that the parser did not validate
		// the CVSS header.
		Vector:         "000003.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		ExpectedCVSS31: nil,
		ExpectedErr:    ErrInvalidCVSSHeader,
	},
}

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss31, err := ParseVector(vector)

		if err != nil {
			if cvss31 != nil {
				t.Fatal("not supposed to get a CVSS31 when en error is returned")
			}
			return
		}

		// Check CVSS v3.1 headers
		cvss31vector := cvss31.Vector()
		if vector[:len("CVSS:3.1")] != "CVSS:3.1" {
			t.Fatalf("invalid CVSS v3.1 header of %s", vector)
		}
		if cvss31vector[:len("CVSS:3.1")] != "CVSS:3.1" {
			t.Fatalf("invalid CVSS v3.1 header of %s", cvss31vector)
		}

		// Check the cvss31's vector gives as much info as input vector
		newCVSS31, err := ParseVector(cvss31vector)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cvss31, newCVSS31) {
			t.Fatalf("cvss31's vector %s does not give as much info as input vector %s", cvss31vector, vector)
		}
	})
}
