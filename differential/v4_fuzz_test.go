package differential_test

import "testing"

func v4corpus(f *testing.F) {
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
	f.Add("CVSS:4.0/UI:N/AC:L/VA:N/AT:N/PR:H/VC:L/SI:N/VI:L/SC:N/AV:N/SA:N")
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/SC:N/VI:L/SI:N/VA:N/SA:N/E:A/CR:M/IR:X/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:H/MSC:H/MSI:X/MSA:S/S:N/AU:X/R:I/V:C/RE:M/U:Amber")
}
