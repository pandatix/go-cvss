package gocvss20

import (
	"math"
	"strings"
	"sync"
	"unsafe"
)

var order = [][]string{
	{"AV", "AC", "Au", "C", "I", "A"}, // Base metrics
	{"E", "RL", "RC"},                 // Temporal metrics
	{"CDP", "TD", "CR", "IR", "AR"},   // Environmental metrics
}

// ParseVector parses a CVSS v2.0 vector.
func ParseVector(vector string) (*CVSS20, error) {
	// Split parts
	pts := split(vector)

	// Work on each CVSS part
	cvss20 := &CVSS20{
		u0: 0,
		u1: 0,
		u2: 0,
		u3: 0,
	}

	slci := 0
	i := 0
	for _, pt := range pts {
		abv, v, _ := strings.Cut(pt, ":")
		tgt := ""
		switch slci {
		case 0, 2:
			tgt = order[slci][i]
		case 1:
			tgt = order[1][i]
			if i == 0 && tgt != abv {
				slci++
				tgt = order[2][0]
			}
		default:
			return nil, &ErrDefinedN{Abv: abv}
		}
		if abv != tgt {
			return nil, ErrInvalidMetricOrder
		}

		if err := cvss20.Set(abv, v); err != nil {
			return nil, err
		}

		// Go to next element in slice, or next slice if fully consumed
		i++
		if i == len(order[slci]) {
			slci++
			i = 0
		}
	}
	// Check whole last metric group is specified in vector (=> i == 0)
	if i != 0 {
		return nil, ErrTooShortVector
	}

	return cvss20, nil
}

var splitPool = sync.Pool{
	New: func() any {
		return make([]string, 14)
	},
}

func split(vector string) []string {
	partsPtr := splitPool.Get()
	defer splitPool.Put(partsPtr)
	parts := partsPtr.([]string)

	start := 0
	curr := 0
	l := len(vector)
	i := 0
	for ; i < l; i++ {
		if vector[i] == '/' {
			parts[curr] = vector[start:i]

			start = i + 1
			curr++

			if curr == 13 {
				break
			}
		}
	}
	parts[curr] = vector[start:]
	return parts[:curr+1]
}

func (cvss20 CVSS20) Vector() string {
	l := lenVec(&cvss20)
	b := make([]byte, 0, l)

	// Base
	app(&b, "AV:", cvss20.get("AV"))
	app(&b, "/AC:", cvss20.get("AC"))
	app(&b, "/Au:", cvss20.get("Au"))
	app(&b, "/C:", cvss20.get("C"))
	app(&b, "/I:", cvss20.get("I"))
	app(&b, "/A:", cvss20.get("A"))

	// Temporal
	e, rl, rc := cvss20.get("E"), cvss20.get("RL"), cvss20.get("RC")
	if e != "ND" || rl != "ND" || rc != "ND" {
		app(&b, "/E:", e)
		app(&b, "/RL:", rl)
		app(&b, "/RC:", rc)
	}

	// Environmental
	cdp, td, cr, ir, ar := cvss20.get("CDP"), cvss20.get("TD"), cvss20.get("CR"), cvss20.get("IR"), cvss20.get("AR")
	if cdp != "ND" || td != "ND" || cr != "ND" || ir != "ND" || ar != "ND" {
		app(&b, "/CDP:", cdp)
		app(&b, "/TD:", td)
		app(&b, "/CR:", cr)
		app(&b, "/IR:", ir)
		app(&b, "/AR:", ar)
	}

	return *(*string)(unsafe.Pointer(&b))
}

func lenVec(cvss20 *CVSS20) int {
	// Base:
	// - AV, AC, Au: 4
	// - C, I, A: 3
	// - separators: 5
	// Total: 3*4 + 3*3 + 5 = 26
	l := 26

	// Temporal:
	// - E: 2 + len(v)
	// - RL: 3 + len(v)
	// - RC: 3 + len(v)
	// - separators: 3
	// Total: 11 + 3*len(v)
	e, rl, rc := cvss20.get("E"), cvss20.get("RL"), cvss20.get("RC")
	if e != "ND" || rl != "ND" || rc != "ND" {
		l += 11 + len(e) + len(rl) + len(rc)
	}

	// Environmental:
	// - CDP: 4 + len(v)
	// - TD: 3 + len(v)
	// - CR, IR, AR: 3 + len(v)
	// - separators: 5
	// Total: 21 + 5*len(v)
	cdp, td, cr, ir, ar := cvss20.get("CDP"), cvss20.get("TD"), cvss20.get("CR"), cvss20.get("IR"), cvss20.get("AR")
	if cdp != "ND" || td != "ND" || cr != "ND" || ir != "ND" || ar != "ND" {
		l += 21 + len(cdp) + len(td) + len(cr) + len(ir) + len(ar)
	}

	return l
}

func app(b *[]byte, pre, v string) {
	*b = append(*b, pre...)
	*b = append(*b, v...)
}

// CVSS20 embeds all the metric values defined by the CVSS v2.0
// rev2 specification.
type CVSS20 struct {
	u0, u1, u2, u3 uint8
}

func (cvss20 CVSS20) Get(abv string) (r string, err error) {
	switch abv {
	// Base
	case "AV":
		v := (cvss20.u0 & 0b11000000) >> 6
		switch v {
		case av_l:
			r = "L"
		case av_a:
			r = "A"
		case av_n:
			r = "N"
		}
	case "AC":
		v := (cvss20.u0 & 0b00110000) >> 4
		switch v {
		case ac_l:
			r = "L"
		case ac_m:
			r = "M"
		case ac_h:
			r = "H"
		}
	case "Au":
		v := (cvss20.u0 & 0b00001100) >> 2
		switch v {
		case au_m:
			r = "M"
		case au_s:
			r = "S"
		case au_n:
			r = "N"
		}
	case "C":
		v := cvss20.u0 & 0b00000011
		switch v {
		case cia_n:
			r = "N"
		case cia_p:
			r = "P"
		case cia_c:
			r = "C"
		}
	case "I":
		v := (cvss20.u1 & 0b11000000) >> 6
		switch v {
		case cia_n:
			r = "N"
		case cia_p:
			r = "P"
		case cia_c:
			r = "C"
		}
	case "A":
		v := (cvss20.u1 & 0b00110000) >> 4
		switch v {
		case cia_n:
			r = "N"
		case cia_p:
			r = "P"
		case cia_c:
			r = "C"
		}

	// Temporal
	case "E":
		v := (cvss20.u1 & 0b00001110) >> 1
		switch v {
		case e_nd:
			r = "ND"
		case e_u:
			r = "U"
		case e_poc:
			r = "POC"
		case e_f:
			r = "F"
		case e_h:
			r = "H"
		}
	case "RL":
		v := ((cvss20.u1 & 0b00000001) << 2) | ((cvss20.u2 & 0b11000000) >> 6)
		switch v {
		case rl_nd:
			r = "ND"
		case rl_of:
			r = "OF"
		case rl_tf:
			r = "TF"
		case rl_w:
			r = "W"
		case rl_u:
			r = "U"
		}
	case "RC":
		v := (cvss20.u2 & 0b00110000) >> 4
		switch v {
		case rc_nd:
			r = "ND"
		case rc_uc:
			r = "UC"
		case rc_ur:
			r = "UR"
		case rc_c:
			r = "C"
		}

	// Environmental
	case "CDP":
		v := (cvss20.u2 & 0b00001110) >> 1
		switch v {
		case cdp_nd:
			r = "ND"
		case cdp_n:
			r = "N"
		case cdp_l:
			r = "L"
		case cdp_lm:
			r = "LM"
		case cdp_mh:
			r = "MH"
		case cdp_h:
			r = "H"
		}
	case "TD":
		v := ((cvss20.u2 & 0b00000001) << 2) | ((cvss20.u3 & 0b11000000) >> 6)
		switch v {
		case td_nd:
			r = "ND"
		case td_n:
			r = "N"
		case td_l:
			r = "L"
		case td_m:
			r = "M"
		case td_h:
			r = "H"
		}
	case "CR":
		v := (cvss20.u3 & 0b00110000) >> 4
		switch v {
		case ciar_nd:
			r = "ND"
		case ciar_l:
			r = "L"
		case ciar_m:
			r = "M"
		case ciar_h:
			r = "H"
		}
	case "IR":
		v := (cvss20.u3 & 0b00001100) >> 2
		switch v {
		case ciar_nd:
			r = "ND"
		case ciar_l:
			r = "L"
		case ciar_m:
			r = "M"
		case ciar_h:
			r = "H"
		}
	case "AR":
		v := cvss20.u3 & 0b00000011
		switch v {
		case ciar_nd:
			r = "ND"
		case ciar_l:
			r = "L"
		case ciar_m:
			r = "M"
		case ciar_h:
			r = "H"
		}
	default:
		return "", &ErrInvalidMetric{Abv: abv}
	}
	return
}

// get is used for internal purposes only.
func (cvss20 CVSS20) get(abv string) string {
	str, err := cvss20.Get(abv)
	if err != nil {
		panic(err)
	}
	return str
}

func (cvss20 *CVSS20) Set(abv string, value string) error {
	switch abv {
	// Base
	case "AV":
		v, err := validate(value, []string{"L", "A", "N"})
		if err != nil {
			return err
		}
		cvss20.u0 = (cvss20.u0 & 0b00111111) | (v << 6)
	case "AC":
		v, err := validate(value, []string{"L", "M", "H"})
		if err != nil {
			return err
		}
		cvss20.u0 = (cvss20.u0 & 0b11001111) | (v << 4)
	case "Au":
		v, err := validate(value, []string{"M", "S", "N"})
		if err != nil {
			return err
		}
		cvss20.u0 = (cvss20.u0 & 0b11110011) | (v << 2)
	case "C":
		v, err := validate(value, []string{"N", "P", "C"})
		if err != nil {
			return err
		}
		cvss20.u0 = (cvss20.u0 & 0b11111100) | v
	case "I":
		v, err := validate(value, []string{"N", "P", "C"})
		if err != nil {
			return err
		}
		cvss20.u1 = (cvss20.u1 & 0b00111111) | (v << 6)
	case "A":
		v, err := validate(value, []string{"N", "P", "C"})
		if err != nil {
			return err
		}
		cvss20.u1 = (cvss20.u1 & 0b11001111) | (v << 4)

	// Temporal
	case "E":
		v, err := validate(value, []string{"ND", "U", "POC", "F", "H"})
		if err != nil {
			return err
		}
		cvss20.u1 = (cvss20.u1 & 0b11110001) | (v << 1)
	case "RL":
		v, err := validate(value, []string{"ND", "OF", "TF", "W", "U"})
		if err != nil {
			return err
		}
		cvss20.u1 = (cvss20.u1 & 0b11111110) | ((v & 0b100) >> 2)
		cvss20.u2 = (cvss20.u2 & 0b00111111) | ((v & 0b011) << 6)
	case "RC":
		v, err := validate(value, []string{"ND", "UC", "UR", "C"})
		if err != nil {
			return err
		}
		cvss20.u2 = (cvss20.u2 & 0b11001111) | (v << 4)

	// Environmental
	case "CDP":
		v, err := validate(value, []string{"ND", "N", "L", "LM", "MH", "H"})
		if err != nil {
			return err
		}
		cvss20.u2 = (cvss20.u2 & 0b11110001) | (v << 1)
	case "TD":
		v, err := validate(value, []string{"ND", "N", "L", "M", "H"})
		if err != nil {
			return err
		}
		cvss20.u2 = (cvss20.u2 & 0b11111110) | ((v & 0b100) >> 2)
		cvss20.u3 = (cvss20.u3 & 0b00111111) | ((v & 0b011) << 6)
	case "CR":
		v, err := validate(value, []string{"ND", "L", "M", "H"})
		if err != nil {
			return err
		}
		cvss20.u3 = (cvss20.u3 & 0b11001111) | (v << 4)
	case "IR":
		v, err := validate(value, []string{"ND", "L", "M", "H"})
		if err != nil {
			return err
		}
		cvss20.u3 = (cvss20.u3 & 0b11110011) | (v << 2)
	case "AR":
		v, err := validate(value, []string{"ND", "L", "M", "H"})
		if err != nil {
			return err
		}
		cvss20.u3 = (cvss20.u3 & 0b11111100) | v
	default:
		return &ErrInvalidMetric{Abv: abv}
	}
	return nil
}

// validate returns the index of value in enabled if matches.
// enabled values have to match the values.go constants order.
func validate(value string, enabled []string) (i uint8, err error) {
	// Check is valid
	for _, enbl := range enabled {
		if value == enbl {
			return i, nil
		}
		i++
	}
	return 0, ErrInvalidMetricValue
}

// BaseScore returns the CVSS v2.0's base score.
func (cvss20 CVSS20) BaseScore() float64 {
	impact := cvss20.Impact()
	fimpact := 0.0
	if impact != 0 {
		fimpact = 1.176
	}
	exploitability := cvss20.Exploitability()
	return roundTo1Decimal(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fimpact)
}

func (cvss20 CVSS20) Impact() float64 {
	return 10.41 * (1 - (1-cia(cvss20.get("C")))*(1-cia(cvss20.get("I")))*(1-cia(cvss20.get("A"))))
}

func (cvss20 CVSS20) Exploitability() float64 {
	return 20 * accessVector(cvss20.get("AV")) * accessComplexity(cvss20.get("AC")) * authentication(cvss20.get("Au"))
}

// TemporalScore returns the CVSS v2.0's temporal score.
func (cvss20 CVSS20) TemporalScore() float64 {
	return roundTo1Decimal(cvss20.BaseScore() * exploitability(cvss20.get("E")) * remediationLevel(cvss20.get("RL")) * reportConfidence(cvss20.get("RC")))
}

// EnvironmentalScore returns the CVSS v2.0's environmental score.
func (cvss20 CVSS20) EnvironmentalScore() float64 {
	// Recompute base score
	adjustedImpact := math.Min(10, 10.41*(1-(1-cia(cvss20.get("C"))*ciar(cvss20.get("CR")))*(1-cia(cvss20.get("I"))*ciar(cvss20.get("IR")))*(1-cia(cvss20.get("A"))*ciar(cvss20.get("AR")))))
	fimpactBase := 0.0
	if adjustedImpact != 0 {
		fimpactBase = 1.176
	}
	expltBase := 20 * accessVector(cvss20.get("AV")) * accessComplexity(cvss20.get("AC")) * authentication(cvss20.get("Au"))
	recBase := roundTo1Decimal(((0.6 * adjustedImpact) + (0.4 * expltBase) - 1.5) * fimpactBase)
	adjustedTemporal := roundTo1Decimal(recBase * exploitability(cvss20.get("E")) * remediationLevel(cvss20.get("RL")) * reportConfidence(cvss20.get("RC")))
	return roundTo1Decimal((adjustedTemporal + (10-adjustedTemporal)*collateralDamagePotential(cvss20.get("CDP"))) * targetDistribution(cvss20.get("TD")))
}

// Helpers to compute CVSS v2.0 scores.

func accessVector(v string) float64 {
	switch v {
	case "L":
		return 0.395
	case "A":
		return 0.646
	case "N":
		return 1.0
	default:
		panic(ErrInvalidMetricValue)
	}
}

func accessComplexity(v string) float64 {
	switch v {
	case "H":
		return 0.35
	case "M":
		return 0.61
	case "L":
		return 0.71
	default:
		panic(ErrInvalidMetricValue)
	}
}

func authentication(v string) float64 {
	switch v {
	case "M":
		return 0.45
	case "S":
		return 0.56
	case "N":
		return 0.704
	default:
		panic(ErrInvalidMetricValue)
	}
}

func cia(v string) float64 {
	switch v {
	case "N":
		return 0.0
	case "P":
		return 0.275
	case "C":
		return 0.660
	default:
		panic(ErrInvalidMetricValue)
	}
}

func exploitability(v string) float64 {
	switch v {
	case "U":
		return 0.85
	case "POC":
		return 0.9
	case "F":
		return 0.95
	case "H":
		return 1.00
	case "ND":
		return 1.00
	default:
		panic(ErrInvalidMetricValue)
	}
}

func remediationLevel(v string) float64 {
	switch v {
	case "OF":
		return 0.87
	case "TF":
		return 0.90
	case "W":
		return 0.95
	case "U":
		return 1.00
	case "ND":
		return 1.00
	default:
		panic(ErrInvalidMetricValue)
	}
}

func reportConfidence(v string) float64 {
	switch v {
	case "UC":
		return 0.90
	case "UR":
		return 0.95
	case "C":
		return 1.00
	case "ND":
		return 1.00
	default:
		panic(ErrInvalidMetricValue)
	}
}

func collateralDamagePotential(v string) float64 {
	switch v {
	case "N":
		return 0
	case "L":
		return 0.1
	case "LM":
		return 0.3
	case "MH":
		return 0.4
	case "H":
		return 0.5
	case "ND":
		return 0
	default:
		panic(ErrInvalidMetricValue)
	}
}

func targetDistribution(v string) float64 {
	switch v {
	case "N":
		return 0
	case "L":
		return 0.25
	case "M":
		return 0.75
	case "H":
		return 1.00
	case "ND":
		return 1.00
	default:
		panic(ErrInvalidMetricValue)
	}
}

func ciar(v string) float64 {
	switch v {
	case "L":
		return 0.5
	case "M":
		return 1.0
	case "H":
		return 1.51
	case "ND":
		return 1.0
	default:
		panic(ErrInvalidMetricValue)
	}
}

// this helper is not specified, so we literally round the value
// to 1 decimal.
func roundTo1Decimal(x float64) float64 {
	return math.RoundToEven(x*10) / 10
}
