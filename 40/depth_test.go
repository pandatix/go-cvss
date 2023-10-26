package gocvss40

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_DepthEQ1(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Filter all combinations in MacroVectors
	avs := []string{"N", "A", "L", "P"}
	prs := []string{"N", "L", "H"}
	uis := []string{"N", "P", "A"}
	combs := make([]*CVSS40, 0, len(avs)*len(prs)*len(uis))
	for _, av := range avs {
		for _, pr := range prs {
			for _, ui := range uis {
				vec := &CVSS40{}
				_ = vec.Set("AV", av)
				_ = vec.Set("PR", pr)
				_ = vec.Set("UI", ui)
				combs = append(combs, vec)
			}
		}
	}
	mvs := map[int][]*CVSS40{}
	for _, vec := range combs {
		eq1, _, _, _, _, _ := vec.macroVector()
		mvs[eq1] = append(mvs[eq1], vec)
	}

	// Find the highests and lowests severity vectors for each MacroVector
	depths := map[int]float64{}
	for level, mv := range mvs {
		// 1. Find the min/max distances in this MacroVector
		min, max := 99., 0.
		for _, vec := range mv {
			d := severityDistance(vec, "AV:N/PR:N/UI:N")
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}

		// 2. Compute depths by the difference between them
		depths[level] = abs(max - min)
	}

	// Check for each EQ MacroVector that its matches the efficient implementation depths
	for lvl := 0; lvl < len(depths); lvl++ {
		assert.Equal(getDepth(1, lvl), depths[lvl], "unequal MacroVector value for level %d", lvl)
	}
}

func Test_U_DepthEQ2(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Filter all combinations in MacroVectors
	acs := []string{"L", "H"}
	ats := []string{"N", "P"}
	combs := make([]*CVSS40, 0, len(acs)*len(ats))
	for _, ac := range acs {
		for _, at := range ats {
			vec := &CVSS40{}
			_ = vec.Set("AC", ac)
			_ = vec.Set("AT", at)
			combs = append(combs, vec)
		}
	}

	mvs := map[int][]*CVSS40{}
	for _, vec := range combs {
		_, eq2, _, _, _, _ := vec.macroVector()
		mvs[eq2] = append(mvs[eq2], vec)
	}

	// Find the highests and lowests severity vectors for each MacroVector
	depths := map[int]float64{}
	for level, mv := range mvs {
		// 1. Find the min/max distances in this MacroVector
		min, max := 99., 0.
		for _, vec := range mv {
			d := severityDistance(vec, "AC:L/AT:N")
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}

		// 2. Compute depths by the difference between them
		depths[level] = abs(max - min)
	}

	// Check for each EQ MacroVector that its matches the efficient implementation depths
	for lvl := 0; lvl < len(depths); lvl++ {
		assert.Equal(getDepth(2, lvl), depths[lvl], "unequal MacroVector value for level %d", lvl)
	}
}

func Test_U_DepthEQ4(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Filter all combinations in MacroVectors
	scs := []string{"H", "L", "N"}
	msis := []string{"S", "H", "L", "N"}
	msas := []string{"S", "H", "L", "N"}
	combs := make([]*CVSS40, 0, len(scs)*len(msis)*len(msas))
	for _, sc := range scs {
		for _, msi := range msis {
			for _, msa := range msas {
				vec := &CVSS40{}
				_ = vec.Set("SC", sc)
				_ = vec.Set("MSI", msi)
				_ = vec.Set("MSA", msa)
				combs = append(combs, vec)
			}
		}
	}
	mvs := map[int][]*CVSS40{}
	for _, vec := range combs {
		_, _, _, eq4, _, _ := vec.macroVector()
		mvs[eq4] = append(mvs[eq4], vec)
	}

	// Find the highests and lowests severity vectors for each MacroVector
	depths := map[int]float64{}
	for level, mv := range mvs {
		// 1. Find the min/max distances in this MacroVector
		min, max := 99., 0.
		for _, vec := range mv {
			d := severityDistance(vec, "SC:H/SI:S/SA:S")
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}

		// 2. Compute depths by the difference between them
		depths[level] = abs(max - min)
	}

	// Check for each EQ MacroVector that its matches the efficient implementation depths
	for lvl := 0; lvl < len(depths); lvl++ {
		assert.Equal(getDepth(4, lvl), depths[lvl], "unequal MacroVector value for level %d", lvl)
	}
}

func Test_U_DepthEQ5(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Filter all combinations in MacroVectors
	es := []string{"X", "A", "P", "U"}
	combs := make([]*CVSS40, 0, len(es))
	for _, e := range es {
		vec := &CVSS40{}
		_ = vec.Set("E", e)
		combs = append(combs, vec)
	}
	mvs := map[int][]*CVSS40{}
	for _, vec := range combs {
		_, _, _, _, eq5, _ := vec.macroVector()
		mvs[eq5] = append(mvs[eq5], vec)
	}

	// Find the highests and lowests severity vectors for each MacroVector
	depths := map[int]float64{}
	for level, mv := range mvs {
		// 1. Find the min/max distances in this MacroVector
		min, max := 99., 0.
		for _, vec := range mv {
			d := severityDistance(vec, "E:A")
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}

		// 2. Compute depths by the difference between them
		depths[level] = abs(max - min)
	}

	// Check for each EQ MacroVector that its matches the efficient implementation depths
	for lvl := 0; lvl < len(depths); lvl++ {
		assert.Equal(getDepth(5, lvl), depths[lvl], "unequal MacroVector value for level %d", lvl)
	}
}

func Test_U_DepthEQ3EQ6(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	// Filter all combinations in MacroVectors
	vcs := []string{"H", "L", "N"}
	vis := []string{"H", "L", "N"}
	vas := []string{"H", "L", "N"}
	crs := []string{"X", "H", "M", "L"}
	irs := []string{"X", "H", "M", "L"}
	ars := []string{"X", "H", "M", "L"}
	combs := make([]*CVSS40, 0, len(vcs)*len(vis)*len(vas)*len(crs)*len(irs)*len(ars))
	for _, vc := range vcs {
		for _, vi := range vis {
			for _, va := range vas {
				for _, cr := range crs {
					for _, ir := range irs {
						for _, ar := range ars {
							vec := &CVSS40{}
							_ = vec.Set("VC", vc)
							_ = vec.Set("VI", vi)
							_ = vec.Set("VA", va)
							_ = vec.Set("CR", cr)
							_ = vec.Set("IR", ir)
							_ = vec.Set("AR", ar)
							combs = append(combs, vec)
						}
					}
				}
			}
		}
	}
	mvs := map[int]map[int][]*CVSS40{}
	for _, vec := range combs {
		_, _, eq3, _, _, eq6 := vec.macroVector()
		if mvs[eq3] == nil {
			mvs[eq3] = map[int][]*CVSS40{}
		}
		mvs[eq3][eq6] = append(mvs[eq3][eq6], vec)
	}

	// Find the highests and lowests severity vectors for each MacroVector
	depths := map[int]map[int]float64{}
	for eq3lvl, eq6 := range mvs {
		if depths[eq3lvl] == nil {
			depths[eq3lvl] = map[int]float64{}
		}
		for eq6lvl, mv := range eq6 {
			// 1. Find the min/max distances in this MacroVector
			min, max := 99., 0.
			for _, vec := range mv {
				d := severityDistance(vec, "VC:H/VI:H/VA:H/CR:H/IR:H/AR:H")
				if d < min {
					min = d
				}
				if d > max {
					max = d
				}
			}

			// 2. Compute depths by the difference between them
			depths[eq3lvl][eq6lvl] = abs(max - min)
		}
	}

	// Check for each EQ MacroVector that its matches the efficient implementation depths
	for eq3lvl, eq6 := range depths {
		for eq6lvl, depth := range eq6 {
			assert.Equal(getDepthEQ3EQ6(eq3lvl, eq6lvl), depth, "unequal MacroVector value for EQ3 level %d and EQ6 level %d", eq3lvl, eq6lvl)
		}
	}
}
