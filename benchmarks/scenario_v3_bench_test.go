package benchmarks

import (
	"testing"

	bunji2 "github.com/bunji2/cvssv3"
	goark3 "github.com/goark/go-cvss/v3/metric"
	pandatix31 "github.com/pandatix/go-cvss/31"
)

const (
	cvss31vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:L"
)

// This benchmarks the parsing function on a CVSS v3.1 vector.
// The vector contains only Base metrics as it is the most common
// case in the NVD.
func Benchmark_V3_ParseVector(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec *pandatix31.CVSS31
			var err error
			for pb.Next() {
				vec, err = pandatix31.ParseVector(cvss31vector)
			}
			GpandatixVec3 = vec
			Gerr = err
		})
	})
	// umisama/go-cvss can't handle CVSS v3
	b.Run("bunji2/cvssv3", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec bunji2.Vector
			var err error
			for pb.Next() {
				vec, err = bunji2.ParseVector(cvss31vector)
			}
			Gbunji2Vec = vec
			Gerr = err
		})
	})
	b.Run("goark/go-cvss", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec = goark3.NewBase()
			var err error
			for pb.Next() {
				_, err = vec.Decode(cvss31vector)
			}
			Ggoark3Vec = vec
			Gerr = err
		})
	})
}

// This benchmarks the vectorizing function on a CVSS v3.1 vector.
// The returned vector contains only Base metrics as it is the most
// common case in the NVD.
func Benchmark_V3_Vector(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		vec, _ := pandatix31.ParseVector(cvss31vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str = vec.Vector()
			}
			Gstr = str
		})
	})
	// umisama/go-cvss can't handle CVSS v3
	b.Run("bunji2/cvssv3", func(b *testing.B) {
		vec, _ := bunji2.ParseVector(cvss31vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str = vec.String()
			}
			Gstr = str
		})
	})
	b.Run("goark/go-cvss", func(b *testing.B) {
		vec, _ := goark3.NewBase().Decode(cvss31vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str, _ = vec.Encode()
			}
			Gstr = str
		})
	})
}

// This benchmarks the base score computing on a CVSS v3.1 vector.
// Only the base score is computed
func Benchmark_V3_BaseScore(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		vec, _ := pandatix31.ParseVector(cvss31vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.BaseScore()
			}
			Gf = f
		})
	})
	// umisama/go-cvss can't handle CVSS v3
	b.Run("bunji2/cvssv3", func(b *testing.B) {
		vec, _ := bunji2.ParseVector(cvss31vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.BaseScore()
			}
			Gf = f
		})
	})
	b.Run("goark/go-cvss", func(b *testing.B) {
		vec, _ := goark3.NewBase().Decode(cvss31vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.Score()
			}
			Gf = f
		})
	})
}

var (
	GpandatixVec3 *pandatix31.CVSS31
	Gbunji2Vec    bunji2.Vector
	Ggoark3Vec    *goark3.Base
	Gerr          error
	Gstr          string
	Gf            float64
)
