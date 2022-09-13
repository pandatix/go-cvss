package gocvss20_test

import (
	"testing"

	gocvss20 "github.com/pandatix/go-cvss/20"
)

var Gcvss20 *gocvss20.CVSS20
var Gerr error

func BenchmarkParseVector_Base(b *testing.B) {
	benchmarkParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C", b)
}

func BenchmarkParseVector_WithTempAndEnv(b *testing.B) {
	benchmarkParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M", b)
}

func benchmarkParseVector(vector string, b *testing.B) {
	var cvss20 *gocvss20.CVSS20
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cvss20, err = gocvss20.ParseVector(vector)
	}
	Gcvss20 = cvss20
	Gerr = err
}

var Gstr string

func BenchmarkCVSS20Vector(b *testing.B) {
	cvss20, _ := gocvss20.ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	var str string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str = cvss20.Vector()
	}
	Gstr = str
}

var Gget string

func BenchmarkCVSS20Get(b *testing.B) {
	const abv = "Au"
	cvss20, _ := gocvss20.ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	var get string
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get, err = cvss20.Get(abv)
	}
	Gget = get
	Gerr = err
}

func BenchmarkCVSS20Set(b *testing.B) {
	const abv = "Au"
	const value = "S"
	cvss20, _ := gocvss20.ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = cvss20.Set(abv, value)
	}
	Gerr = err
}

var Gscore float64

func BenchmarkCVSS20BaseScore(b *testing.B) {
	var score float64
	cvss20, _ := gocvss20.ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss20.BaseScore()
	}
	Gscore = score
}

func BenchmarkCVSS20TemporalScore(b *testing.B) {
	var score float64
	cvss20, _ := gocvss20.ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss20.TemporalScore()
	}
	Gscore = score
}

func BenchmarkCVSS20EnvironmentalScore(b *testing.B) {
	var score float64
	cvss20, _ := gocvss20.ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score = cvss20.EnvironmentalScore()
	}
	Gscore = score
}
