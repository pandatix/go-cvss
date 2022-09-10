package gocvss30_test

import (
	"testing"

	gocvss30 "github.com/pandatix/go-cvss/30"
)

var Gcvss30 *gocvss30.CVSS30
var Gerr error

func BenchmarkParseVector_Base(b *testing.B) {
	benchmarkParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", b)
}

func BenchmarkParseVector_WithTempAndEnv(b *testing.B) {
	benchmarkParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RL:O/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H", b)
}

func benchmarkParseVector(vector string, b *testing.B) {
	var cvss30 *gocvss30.CVSS30
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cvss30, err = gocvss30.ParseVector(vector)
	}
	Gcvss30 = cvss30
	Gerr = err
}

var Gstr string

func BenchmarkCVSS30Vector(b *testing.B) {
	cvss30, _ := gocvss30.ParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	var str string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str = cvss30.Vector()
	}
	Gstr = str
}

var Gget string

func BenchmarkCVSS30Get(b *testing.B) {
	const abv = "UI"
	cvss30, _ := gocvss30.ParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	var get string
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get, err = cvss30.Get(abv)
	}
	Gget = get
	Gerr = err
}

func BenchmarkCVSS30Set(b *testing.B) {
	const abv = "UI"
	const value = "R"
	cvss30, _ := gocvss30.ParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = cvss30.Set(abv, value)
	}
	Gerr = err
}

var Gscore float64

func BenchmarkCVSS30BaseScore(b *testing.B) {
	var score float64
	cvss30, _ := gocvss30.ParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss30.BaseScore()
	}
	Gscore = score
}

func BenchmarkCVSS30TemporalScore(b *testing.B) {
	var score float64
	cvss30, _ := gocvss30.ParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss30.TemporalScore()
	}
	Gscore = score
}

func BenchmarkCVSS30EnvironmentalScore(b *testing.B) {
	var score float64
	cvss30, _ := gocvss30.ParseVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:U/RC:C/CR:H/IR:M/MUI:R/MC:H/MI:H/MA:H")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss30.EnvironmentalScore()
	}
	Gscore = score
}
