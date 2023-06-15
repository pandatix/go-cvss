package benchmarks

import (
	"testing"

	pandatix40 "github.com/pandatix/go-cvss/40"
)

const (
	cvss40vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
)

// This benchmarks the parsing function on a CVSS v4.0 vector.
// The vector contains only Base metrics as it is the most common
// case in the NVD.
func Benchmark_V4_ParseVector(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec *pandatix40.CVSS40
			var err error
			for pb.Next() {
				vec, err = pandatix40.ParseVector(cvss40vector)
			}
			GpandatixVec4 = vec
			Gerr = err
		})
	})
}

// This benchmarks the vectorizing function on a CVSS v4.0 vector.
// The returned vector contains only Base metrics as it is the most
// common case in the NVD.
func Benchmark_V4_Vector(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		vec, _ := pandatix40.ParseVector(cvss40vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str = vec.Vector()
			}
			Gstr = str
		})
	})
}

// This benchmarks the score computing on a CVSS v4.0 vector.
// Only the base score is computed.
func Benchmark_V4_BaseScore(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		vec, _ := pandatix40.ParseVector(cvss40vector)
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
	GpandatixVec4 *pandatix40.CVSS40
)
