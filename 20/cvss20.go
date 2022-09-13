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
	pts, l := split(vector)
	if l != 6 && l != 9 && l != 14 {
		return nil, ErrTooShortVector
	}
	pts = pts[:l]

	// Work on each CVSS part
	cvss20 := &CVSS20{
		base: base{},
		temporal: temporal{
			exploitability:   "ND",
			remediationLevel: "ND",
			reportConfidence: "ND",
		},
		environmental: environmental{
			collateralDamagePotential:  "ND",
			targetDistribution:         "ND",
			confidentialityRequirement: "ND",
			integrityRequirement:       "ND",
			availabilityRequirement:    "ND",
		},
	}

	slci := 0
	i := 0
	for _, pt := range pts {
		abv, v, _ := strings.Cut(pt, ":")
		if slci == 4 {
			return nil, &ErrDefinedN{Abv: abv}
		}
		if abv != order[slci][i] {
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

	return cvss20, nil
}

var splitPool = sync.Pool{
	New: func() any {
		return make([]string, 14)
	},
}

func split(vector string) ([]string, int) {
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
	return parts, curr + 1
}

func (cvss20 CVSS20) Vector() string {
	l := lenVec(&cvss20)
	b := make([]byte, 0, l)

	// Base
	app(&b, "AV:", cvss20.accessVector)
	app(&b, "/AC:", cvss20.accessComplexity)
	app(&b, "/Au:", cvss20.authentication)
	app(&b, "/C:", cvss20.confidentialityImpact)
	app(&b, "/I:", cvss20.integrityImpact)
	app(&b, "/A:", cvss20.availabilityImpact)

	// Temporal
	if cvss20.exploitability != "ND" || cvss20.remediationLevel != "ND" || cvss20.reportConfidence != "ND" {
		app(&b, "/E:", cvss20.exploitability)
		app(&b, "/RL:", cvss20.remediationLevel)
		app(&b, "/RC:", cvss20.reportConfidence)
	}

	// Environmental
	if cvss20.collateralDamagePotential != "ND" || cvss20.targetDistribution != "ND" || cvss20.confidentialityRequirement != "ND" || cvss20.integrityRequirement != "ND" || cvss20.availabilityRequirement != "ND" {
		app(&b, "/CDP:", cvss20.collateralDamagePotential)
		app(&b, "/TD:", cvss20.targetDistribution)
		app(&b, "/CR:", cvss20.confidentialityRequirement)
		app(&b, "/IR:", cvss20.integrityRequirement)
		app(&b, "/AR:", cvss20.availabilityRequirement)
	}

	return *(*string)(unsafe.Pointer(&b))
}

func lenVec(cvss20 *CVSS20) int {
	// Base:
	// - AV, AC, Au: 4
	// - C, I, A: 3
	// - separators: 5
	// Total: 3*4 + 3*3 + 5 = 30
	l := 26

	// Temporal:
	// - E: 2 + len(v)
	// - RL: 3 + len(v)
	// - RC: 3 + len(v)
	// - separators: 3
	// Total: 11 + 3*len(v)
	if cvss20.exploitability != "ND" || cvss20.remediationLevel != "ND" || cvss20.reportConfidence != "ND" {
		l += 11 + len(cvss20.exploitability) + len(cvss20.remediationLevel) + len(cvss20.reportConfidence)
	}

	// Environmental:
	// - CDP: 4 + len(v)
	// - TD: 3 + len(v)
	// - CR, IR, AR: 3 + len(v)
	// - separators: 5
	// Total: 21 + 5*len(v)
	if cvss20.collateralDamagePotential != "ND" || cvss20.targetDistribution != "ND" || cvss20.confidentialityRequirement != "ND" || cvss20.integrityRequirement != "ND" || cvss20.availabilityRequirement != "ND" {
		l += 21 + len(cvss20.collateralDamagePotential) + len(cvss20.targetDistribution) + len(cvss20.confidentialityRequirement) + len(cvss20.integrityRequirement) + len(cvss20.availabilityRequirement)
	}

	return l
}

func app(b *[]byte, pre, v string) {
	*b = append(*b, pre...)
	*b = append(*b, v...)
}

// CVSS20 embeds all the metric values defined by the CVSS v2.0
// rev2 specification.
// Attributes values must not be manipulated directly. Use Get
// and Set methods.
type CVSS20 struct {
	base
	temporal
	environmental
}

// base is the group of metrics defined with such name by the
// first.org CVSS v2.0 rev2 specification.
// Mandatory.
type base struct {
	// AV -> [L,A,N]
	accessVector string
	// AC -> [H,M,L]
	accessComplexity string
	// Au -> [M,S,N]
	authentication string
	// C -> [N,P,C]
	confidentialityImpact string
	// I -> [N,P,C]
	integrityImpact string
	// A -> [N,P,C]
	availabilityImpact string
}

// temporal is the group of metrics defined with such name by the
// first.org CVSS v2.0 rev2 specification.
// Not mandatory.
type temporal struct {
	// E -> [U,POC,F,F,H,ND]
	exploitability string
	// RL -> [OF,TF,W,U,ND]
	remediationLevel string
	// RC -> [UC,UR,C,ND]
	reportConfidence string
}

// environmental is the group of metrics defined with such name by the
// first.org CVSS v2.0 rev2 specification.
// Not mandatory.
type environmental struct {
	// CDP -> [N,L,LM,MH,H,ND]
	collateralDamagePotential string
	// TD -> [N,L,M,H,ND]
	targetDistribution string
	// CR,IR,AR -> [L,M,H,ND]
	confidentialityRequirement string
	integrityRequirement       string
	availabilityRequirement    string
}

func (cvss20 CVSS20) Get(abv string) (string, error) {
	switch abv {
	case "AV":
		return cvss20.accessVector, nil
	case "AC":
		return cvss20.accessComplexity, nil
	case "Au":
		return cvss20.authentication, nil
	case "C":
		return cvss20.confidentialityImpact, nil
	case "I":
		return cvss20.integrityImpact, nil
	case "A":
		return cvss20.availabilityImpact, nil
	case "E":
		return cvss20.exploitability, nil
	case "RL":
		return cvss20.remediationLevel, nil
	case "RC":
		return cvss20.reportConfidence, nil
	case "CDP":
		return cvss20.collateralDamagePotential, nil
	case "TD":
		return cvss20.targetDistribution, nil
	case "CR":
		return cvss20.confidentialityRequirement, nil
	case "IR":
		return cvss20.integrityRequirement, nil
	case "AR":
		return cvss20.availabilityRequirement, nil
	default:
		return "", &ErrInvalidMetric{Abv: abv}
	}
}

func (cvss20 *CVSS20) Set(abv string, value string) error {
	switch abv {
	// Base
	case "AV":
		if err := validate(value, []string{"L", "A", "N"}); err != nil {
			return err
		}
		cvss20.accessVector = value
	case "AC":
		if err := validate(value, []string{"H", "M", "L"}); err != nil {
			return err
		}
		cvss20.accessComplexity = value
	case "Au":
		if err := validate(value, []string{"M", "S", "N"}); err != nil {
			return err
		}
		cvss20.authentication = value
	case "C":
		if err := validate(value, []string{"N", "P", "C"}); err != nil {
			return err
		}
		cvss20.confidentialityImpact = value
	case "I":
		if err := validate(value, []string{"N", "P", "C"}); err != nil {
			return err
		}
		cvss20.integrityImpact = value
	case "A":
		if err := validate(value, []string{"N", "P", "C"}); err != nil {
			return err
		}
		cvss20.availabilityImpact = value
	// Temporal
	case "E":
		if err := validate(value, []string{"U", "POC", "F", "H", "ND"}); err != nil {
			return err
		}
		cvss20.exploitability = value
	case "RL":
		if err := validate(value, []string{"OF", "TF", "W", "U", "ND"}); err != nil {
			return err
		}
		cvss20.remediationLevel = value
	case "RC":
		if err := validate(value, []string{"UC", "UR", "C", "ND"}); err != nil {
			return err
		}
		cvss20.reportConfidence = value
	// Environmental
	case "CDP":
		if err := validate(value, []string{"N", "L", "LM", "MH", "H", "ND"}); err != nil {
			return err
		}
		cvss20.collateralDamagePotential = value
	case "TD":
		if err := validate(value, []string{"N", "L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.targetDistribution = value
	case "CR":
		if err := validate(value, []string{"L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.confidentialityRequirement = value
	case "IR":
		if err := validate(value, []string{"L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.integrityRequirement = value
	case "AR":
		if err := validate(value, []string{"L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.availabilityRequirement = value
	default:
		return &ErrInvalidMetric{Abv: abv}
	}
	return nil
}

func validate(value string, enabled []string) error {
	// Check is valid
	for _, enbl := range enabled {
		if value == enbl {
			return nil
		}
	}
	return ErrInvalidMetricValue
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
	return 10.41 * (1 - (1-cia(cvss20.confidentialityImpact))*(1-cia(cvss20.integrityImpact))*(1-cia(cvss20.availabilityImpact)))
}

func (cvss20 CVSS20) Exploitability() float64 {
	return 20 * accessVector(cvss20.accessVector) * accessComplexity(cvss20.accessComplexity) * authentication(cvss20.authentication)
}

// TemporalScore returns the CVSS v2.0's temporal score.
func (cvss20 CVSS20) TemporalScore() float64 {
	return roundTo1Decimal(cvss20.BaseScore() * exploitability(cvss20.exploitability) * remediationLevel(cvss20.remediationLevel) * reportConfidence(cvss20.reportConfidence))
}

// EnvironmentalScore returns the CVSS v2.0's environmental score.
func (cvss20 CVSS20) EnvironmentalScore() float64 {
	// Recompute base score
	adjustedImpact := math.Min(10, 10.41*(1-(1-cia(cvss20.confidentialityImpact)*ciar(cvss20.confidentialityRequirement))*(1-cia(cvss20.integrityImpact)*ciar(cvss20.integrityRequirement))*(1-cia(cvss20.availabilityImpact)*ciar(cvss20.availabilityRequirement))))
	fimpactBase := 0.0
	if adjustedImpact != 0 {
		fimpactBase = 1.176
	}
	expltBase := 20 * accessVector(cvss20.accessVector) * accessComplexity(cvss20.accessComplexity) * authentication(cvss20.authentication)
	recBase := roundTo1Decimal(((0.6 * adjustedImpact) + (0.4 * expltBase) - 1.5) * fimpactBase)
	adjustedTemporal := roundTo1Decimal(recBase * exploitability(cvss20.exploitability) * remediationLevel(cvss20.remediationLevel) * reportConfidence(cvss20.reportConfidence))
	return roundTo1Decimal((adjustedTemporal + (10-adjustedTemporal)*collateralDamagePotential(cvss20.collateralDamagePotential)) * targetDistribution(cvss20.targetDistribution))
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
