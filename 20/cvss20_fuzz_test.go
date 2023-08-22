package gocvss20

import (
	"testing"
)

var testsParseVector = map[string]struct {
	Vector         string
	ExpectedCVSS20 *CVSS20
	ExpectedErr    error
}{
	"CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392": {
		Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001000,
			u1: 0b00100110,
			u2: 0b01110000,
			u3: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818": {
		Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001010,
			u1: 0b10100110,
			u2: 0b01110000,
			u3: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062": {
		Vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C",
		ExpectedCVSS20: &CVSS20{
			u0: 0b00101010,
			u1: 0b10100100,
			u2: 0b01110000,
			u3: 0b00000000,
		},
		ExpectedErr: nil,
	},
	"all-defined": {
		Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001001,
			u1: 0b01100010,
			u2: 0b01111001,
			u3: 0b00101010,
		},
		ExpectedErr: nil,
	},
	"base-and-environmental": {
		// This test covers the case where the temporal group is
		// not defined. This case can be found in the wild (e.g. NIST).
		Vector: "AV:L/AC:M/Au:S/C:N/I:N/A:P/CDP:N/TD:ND/CR:M/IR:ND/AR:ND",
		ExpectedCVSS20: &CVSS20{
			u0: 0b00010100,
			u1: 0b00010000,
			u2: 0b00000010,
			u3: 0b00100000,
		},
		ExpectedErr: nil,
	},
	"invalid-last-metric": {
		Vector:         "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:ND/AR:H/",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrInvalidMetricValue,
	},
	"invalid-metric-value": {
		Vector:         "AV:L/AC:L/Au:M/C:InVaLiD/I:P/A:N",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrInvalidMetricValue,
	},
	"Fuzz_b0c5c63b20b726efad1741c656ed3c1f9ee8c5dc00bb9c938f3e01d11153d51f": {
		// This fuzz crashers enabled detecting that a CVSS v2.0 vector
		// with not any temporal metric defined but some environmental ones
		// does not export the same string as when parsed.
		// It raises the following question: "does the whole metric group must
		// be completly specified in order for the vector to be valid ?". This
		// does not find an answer in the first.org's specification document,
		// but given the fact that the NVD CVSS v2.0 calculator emits a metric
		// group as soon as one of it's metrics is different from "ND", this
		// implementation took the path of unvalidating it because of a lack of
		// metrics.
		Vector:         "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrTooShortVector,
	},
	"Fuzz_b0c5c63b20b726efad1741c656ed3c1f9ee8c5dc00bb9c938f3e01d11153d51f_verified": {
		// This test case proves the possibility of previous fuzz crasher.
		Vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:ND/AR:ND",
		ExpectedCVSS20: &CVSS20{
			u0: 0b01001010,
			u1: 0b10100000,
			u2: 0b00001011,
			u3: 0b00110000,
		},
		ExpectedErr: nil,
	},
	"Fuzz_50620a37c4a7716a77a14602b4bcc7b02e6f751d0a714ed796d9b04402c745ac": {
		// This fuzz crasher enabled detecting that the split function
		// (comming from the optimization step) was doing an Out-Of-Bounds
		// Write (CWE-787) if the vector was only composed of '/'.
		Vector:         "//////////////",
		ExpectedCVSS20: nil,
		ExpectedErr:    ErrInvalidMetricOrder,
	},
	"CVE-2022-39213": {
		Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M",
		ExpectedCVSS20: &CVSS20{
			u0: 0b10001001,
			u1: 0b01100010,
			u2: 0b01111001,
			u3: 0b00101010,
		},
		ExpectedErr: nil,
	},
}

func FuzzParseVector(f *testing.F) {
	for _, tt := range testsParseVector {
		f.Add(tt.Vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		cvss20, err := ParseVector(vector)

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
