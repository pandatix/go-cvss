package gocvss40

import (
	"fmt"
	"strings"
)

var (
	sevIdx = map[string][]string{
		// Base metrics
		"AV": {"N", "A", "L", "P"},
		"AC": {"L", "H"},
		"AT": {"N", "P"},
		"PR": {"N", "L", "H"},
		"UI": {"N", "P", "A"},
		"VC": {"H", "L", "N"},
		"VI": {"H", "L", "N"},
		"VA": {"H", "L", "N"},
		"SC": {"H", "L", "N"},
		"SI": {"S", "H", "L", "N"},
		"SA": {"S", "H", "L", "N"},
		// Threat metrics
		"E": {"A", "P", "U"},
		// Environmental metrics
		"CR":  {"H", "M", "L"},
		"IR":  {"H", "M", "L"},
		"AR":  {"H", "M", "L"},
		"MAV": {"N", "A", "L", "P"},
		"MAC": {"L", "H"},
		"MAT": {"N", "P"},
		"MPR": {"N", "L", "H"},
		"MUI": {"N", "P", "A"},
		"MVC": {"H", "L", "N"},
		"MVI": {"H", "L", "N"},
		"MVA": {"H", "L", "N"},
		"MSC": {"N", "L", "H"},
		"MSI": {"N", "L", "H", "S"},
		"MSA": {"N", "L", "H", "S"},
	}
)

func severityDiff(vec *CVSS40, metric string) float64 {
	k, v, _ := strings.Cut(metric, ":")
	vek := vec.getComp(k)
	return findSev(k, vek) - findSev(k, v)
}

// Computes the severity distance between a partial vector and an
// already-parsed CVSS v4.0 vector.
// Used for regression testing during depths computation.
func severityDistance(vec *CVSS40, partial string) float64 {
	mp := sevSplit(partial)

	dst := 0.0
	for k := range mp {
		tmp := vec.getComp(k)
		v1 := findSev(k, tmp)
		v2 := findSev(k, mp[k])

		dst += abs(v1 - v2)
	}
	return dst
}

func sevSplit(vec string) map[string]string {
	mp := map[string]string{}
	pts := strings.Split(vec, "/")
	for _, pt := range pts {
		m, v, _ := strings.Cut(pt, ":")
		mp[m] = v
	}
	return mp
}

func findSev(k, v string) float64 {
	slc := sevIdx[k]
	for i, e := range slc {
		if e == v {
			return float64(i)
		}
	}
	panic(fmt.Sprintf("not found %v for %s", v, k))
}

func abs[T int | float64](i T) T {
	if i < 0 {
		return -i
	}
	return i
}
