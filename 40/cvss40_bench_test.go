package gocvss40_test

import (
	"testing"

	gocvss40 "github.com/pandatix/go-cvss/40"
)

var Gcvss40 *gocvss40.CVSS40
var Gerr error

func BenchmarkParseVector_Base(b *testing.B) {
	benchmarkParseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", b)
}

func BenchmarkParseVector_WithTemEnvSup(b *testing.B) {
	benchmarkParseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/SC:N/VI:L/SI:N/VA:N/SA:N/E:A/CR:M/IR:X/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:H/MSC:H/MSI:X/MSA:S/S:N/AU:X/R:I/V:C/RE:M/U:Amber", b)
}

func benchmarkParseVector(vector string, b *testing.B) {
	var cvss40 *gocvss40.CVSS40
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cvss40, err = gocvss40.ParseVector(vector)
	}
	Gcvss40 = cvss40
	Gerr = err
}

var Gstr string

func BenchmarkCVSS40Vector(b *testing.B) {
	cvss40, _ := gocvss40.ParseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/SC:N/VI:L/SI:N/VA:N/SA:N/E:A/CR:M/IR:X/AR:H/MAV:L/MAC:H/MAT:N/MPR:H/MUI:N/MVC:X/MVI:L/MVA:H/MSC:H/MSI:X/MSA:S/S:N/AU:X/R:I/V:C/RE:M/U:Amber")
	var str string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str = cvss40.Vector()
	}
	Gstr = str
}

var Gget string

func BenchmarkCVSS40Get(b *testing.B) {
	const abv = "UI"
	cvss40, _ := gocvss40.ParseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
	var get string
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get, err = cvss40.Get(abv)
	}
	Gget = get
	Gerr = err
}

func BenchmarkCVSS40Set(b *testing.B) {
	const abv = "UI"
	const value = "A"
	cvss40, _ := gocvss40.ParseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = cvss40.Set(abv, value)
	}
	Gerr = err
}
