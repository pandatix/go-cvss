package benchmarks

import (
	"testing"

	facebook2 "github.com/facebookincubator/nvdtools/cvss2"
	goark2 "github.com/goark/go-cvss/v2"
	pandatix20 "github.com/pandatix/go-cvss/20"
	slimsec "github.com/slimsec/cvss"
	umisama "github.com/umisama/go-cvss"
	zntrioVec2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
	zntrio2 "go.zenithar.org/mitre/pkg/services/cvss/v2/vector"
)

const (
	cvss20vector = "AV:N/AC:H/Au:S/C:C/I:N/A:P"
)

func Benchmark_V2_ParseVector(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec *pandatix20.CVSS20
			var err error
			for pb.Next() {
				vec, err = pandatix20.ParseVector(cvss20vector)
			}
			GpandatixVec2 = vec
			Gerr = err
		})
	})
	b.Run("umisama/go-cvss", func(b *testing.B) {
		// workaround as not compliant with the specification
		cvss20vector := "(" + cvss20vector + ")"
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec umisama.Vectors
			var err error
			for pb.Next() {
				vec, err = umisama.ParseVectors(cvss20vector)
			}
			GumisamaVec2 = vec
			Gerr = err
		})
	})
	// bunji2/cvssv3 can't handle CVSS v2
	b.Run("goark/go-cvss", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec = goark2.New()
			var err error
			for pb.Next() {
				err = vec.ImportBaseVector(cvss20vector)
			}
			GgoarkVec2 = vec
			Gerr = err
		})
	})
	b.Run("facebookincubator/nvdtools", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec facebook2.Vector
			var err error
			for pb.Next() {
				vec, err = facebook2.VectorFromString(cvss20vector)
			}
			GfacebookVec2 = vec
			Gerr = err
		})
	})
	// slimsec/cvss can't handle CVSS v2 parsing
	b.Run("zntrio/mitre", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var vec *zntrioVec2.Vector
			var err error
			for pb.Next() {
				vec, err = zntrio2.FromString(cvss20vector)
			}
			Gzntrio2Vec = vec
			Gerr = err
		})
	})
}

// This benchmarks the vectorizing function on a CVSS v2.0 vector.
// The returned vector contains only Base metrics as it is the most
// common case in the NVD.
func Benchmark_V2_Vector(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		vec, _ := pandatix20.ParseVector(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str = vec.Vector()
			}
			Gstr = str
		})
	})
	b.Run("umisama/go-cvss", func(b *testing.B) {
		// workaround as not compliant with the specification
		// Really performant (1 alloc/op) as all lies in the heap so it
		// does not escape until return statement (all lenghts are known)
		cvss20vector := "(" + cvss20vector + ")"
		vec, _ := umisama.ParseVectors(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str = vec.String()
			}
			Gstr = str
		})
	})
	// bunji2/cvssv3 can't handle CVSS v2
	// goark/go-cvss can't handle CVSS v2 vectorizing
	b.Run("facebookincubator/nvdtools", func(b *testing.B) {
		vec, _ := facebook2.VectorFromString(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			for pb.Next() {
				str = vec.String()
			}
			Gstr = str
		})
	})
	// slimsec/cvss can't handle CVSS v2 vectorizing
	b.Run("zntrio/mitre", func(b *testing.B) {
		vec, _ := zntrio2.FromString(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var str string
			var err error
			for pb.Next() {
				str, err = zntrio2.ToString(vec)
			}
			Gstr = str
			Gerr = err
		})
	})
}

// This benchmarks the base score computing on a CVSS v2.0 vector.
// Only the base score is computed
func Benchmark_V2_BaseScore(b *testing.B) {
	b.Run("pandatix/go-cvss", func(b *testing.B) {
		vec, _ := pandatix20.ParseVector(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.BaseScore()
			}
			Gf = f
		})
	})
	b.Run("umisama/go-cvss", func(b *testing.B) {
		// workaround as not compliant with the specification
		cvss20vector := "(" + cvss20vector + ")"
		vec, _ := umisama.ParseVectors(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.BaseScore()
			}
			Gf = f
		})
	})
	// bunji2/cvssv3 can't handle CVSS v2
	b.Run("goark/go-cvss", func(b *testing.B) {
		vec := goark2.New()
		_ = vec.ImportBaseVector(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.Base.Score()
			}
			Gf = f
		})
	})
	b.Run("facebookincubator/nvdtools", func(b *testing.B) {
		vec, _ := facebook2.VectorFromString(cvss20vector)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			for pb.Next() {
				f = vec.BaseScore()
			}
			Gf = f
		})
	})
	b.Run("slimsec/cvss", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var f float64
			var err error
			for pb.Next() {
				f, _ = slimsec.CalculateBaseScore(cvss20vector, 2)
			}
			Gf = f
			Gerr = err
		})
	})
	// zntrio/mitre can't handle base score computing ONLY
}

var (
	GpandatixVec2 *pandatix20.CVSS20
	GgoarkVec2    *goark2.CVSS
	GumisamaVec2  umisama.Vectors
	GfacebookVec2 facebook2.Vector
	Gzntrio2Vec   *zntrioVec2.Vector
)
