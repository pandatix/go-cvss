package gocvss31_test

import (
	"testing"

	gocvss31 "github.com/pandatix/go-cvss/31"
)

var Gcvss31 *gocvss31.CVSS31
var Gerr error

func BenchmarkParseVector_Base(b *testing.B) {
	benchmarkParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", b)
}

func BenchmarkParseVector_WithTempAndEnv(b *testing.B) {
	benchmarkParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RL:O/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H", b)
}

func benchmarkParseVector(vector string, b *testing.B) {
	var cvss31 *gocvss31.CVSS31
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cvss31, err = gocvss31.ParseVector(vector)
	}
	Gcvss31 = cvss31
	Gerr = err
}

var Gstr string

func BenchmarkCVSS31Vector(b *testing.B) {
	cvss31, _ := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	var str string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str = cvss31.Vector()
	}
	Gstr = str
}

var Gget string

func BenchmarkCVSS31Get(b *testing.B) {
	const abv = "UI"
	cvss31, _ := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	var get string
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get, err = cvss31.Get(abv)
	}
	Gget = get
	Gerr = err
}

func BenchmarkCVSS31Set(b *testing.B) {
	const abv = "UI"
	const value = "R"
	cvss31, _ := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = cvss31.Set(abv, value)
	}
	Gerr = err
}

var Gscore float64

func BenchmarkCVSS31BaseScore(b *testing.B) {
	var score float64
	cvss31, _ := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss31.BaseScore()
	}
	Gscore = score
}

func BenchmarkCVSS31TemporalScore(b *testing.B) {
	var score float64
	cvss31, _ := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss31.TemporalScore()
	}
	Gscore = score
}

func BenchmarkCVSS31EnvironmentalScore(b *testing.B) {
	var score float64
	cvss31, _ := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss31.EnvironmentalScore()
	}
	Gscore = score
}
