package gocvss20

import (
	"math"
	"strings"
)

// ParseVector parses a CVSS v2.0 vector.
func ParseVector(vector string) (*CVSS20, error) {
	// Split parts
	pts := strings.Split(vector, "/")
	if len(pts) != 6 && len(pts) != 9 && len(pts) != 14 {
		return nil, ErrTooShortVector
	}

	// Work on each CVSS part
	cvss20 := &CVSS20{
		Base: Base{},
		Temporal: Temporal{
			Exploitability:   "ND",
			RemediationLevel: "ND",
			ReportConfidence: "ND",
		},
		Environmental: Environmental{
			CollateralDamagePotential:  "ND",
			TargetDistribution:         "ND",
			ConfidentialityRequirement: "ND",
			IntegrityRequirement:       "ND",
			AvailabilityRequirement:    "ND",
		},
	}

	// Parse metrics in order
	slcs := [][]string{
		{"AV", "AC", "Au", "C", "I", "A"}, // Base metrics
		{"E", "RL", "RC"},                 // Temporal metrics
		{"CDP", "TD", "CR", "IR", "AR"},   // Environmental metrics
	}
	slci := 0
	currSlc := slcs[slci]
	i := 0
	for _, pt := range pts {
		abv, v, _ := strings.Cut(pt, ":")
		if abv != currSlc[i] {
			return nil, ErrInvalidMetricOrder
		}
		if err := cvss20.Set(abv, v); err != nil {
			return nil, err
		}
		// Go to next element in slice, or next slice if fully consumed
		i++
		if i == len(currSlc) {
			slci++
			currSlc = slcs[slci]
			i = 0
		}
	}

	return cvss20, nil
}

func (cvss20 CVSS20) Vector() string {
	s := ""
	// Base
	s += "AV:" + cvss20.AccessVector
	s += "/AC:" + cvss20.AccessComplexity
	s += "/Au:" + cvss20.Authentication
	s += "/C:" + cvss20.ConfidentialityImpact
	s += "/I:" + cvss20.IntegrityImpact
	s += "/A:" + cvss20.AvailabilityImpact
	// Temporal, if any is defined
	if cvss20.Exploitability != "ND" || cvss20.RemediationLevel != "ND" || cvss20.ReportConfidence != "ND" {
		s += "/E:" + cvss20.Exploitability
		s += "/RL:" + cvss20.RemediationLevel
		s += "/RC:" + cvss20.ReportConfidence
	}
	// Environmental, if any is defined
	if cvss20.CollateralDamagePotential != "ND" || cvss20.TargetDistribution != "ND" || cvss20.ConfidentialityRequirement != "ND" || cvss20.IntegrityRequirement != "ND" || cvss20.AvailabilityRequirement != "ND" {
		s += "/CDP:" + cvss20.CollateralDamagePotential
		s += "/TD:" + cvss20.TargetDistribution
		s += "/CR:" + cvss20.ConfidentialityRequirement
		s += "/IR:" + cvss20.IntegrityRequirement
		s += "/AR:" + cvss20.AvailabilityRequirement
	}
	return s
}

// CVSS20 embeds all the metric values defined by the CVSS v2.0
// rev2 specification.
// Attributes values must not be manipulated directly. Use Get
// and Set methods.
type CVSS20 struct {
	Base
	Temporal
	Environmental
}

// Base is the group of metrics defined with such name by the
// first.org CVSS v2.0 rev2 specification.
// Mandatory.
type Base struct {
	// AV -> [L,A,N]
	AccessVector string
	// AC -> [H,M,L]
	AccessComplexity string
	// Au -> [M,S,N]
	Authentication string
	// C -> [N,P,C]
	ConfidentialityImpact string
	// I -> [N,P,C]
	IntegrityImpact string
	// A -> [N,P,C]
	AvailabilityImpact string
}

// Temporal is the group of metrics defined with such name by the
// first.org CVSS v2.0 rev2 specification.
// Not mandatory.
type Temporal struct {
	// E -> [U,POC,F,F,H,ND]
	Exploitability string
	// RL -> [OF,TF,W,U,ND]
	RemediationLevel string
	// RC -> [UC,UR,C,ND]
	ReportConfidence string
}

// Environmental is the group of metrics defined with such name by the
// first.org CVSS v2.0 rev2 specification.
// Not mandatory.
type Environmental struct {
	// CDP -> [N,L,LM,MH,H,ND]
	CollateralDamagePotential string
	// TD -> [N,L,M,H,ND]
	TargetDistribution string
	// CR,IR,AR -> [L,M,H,ND]
	ConfidentialityRequirement string
	IntegrityRequirement       string
	AvailabilityRequirement    string
}

func (cvss20 CVSS20) Get(abv string) (string, error) {
	switch abv {
	case "AV":
		return cvss20.AccessVector, nil
	case "AC":
		return cvss20.AccessComplexity, nil
	case "Au":
		return cvss20.Authentication, nil
	case "C":
		return cvss20.ConfidentialityImpact, nil
	case "I":
		return cvss20.IntegrityImpact, nil
	case "A":
		return cvss20.AvailabilityImpact, nil
	case "E":
		return cvss20.Exploitability, nil
	case "RL":
		return cvss20.RemediationLevel, nil
	case "RC":
		return cvss20.ReportConfidence, nil
	case "CDP":
		return cvss20.CollateralDamagePotential, nil
	case "TD":
		return cvss20.TargetDistribution, nil
	case "CR":
		return cvss20.ConfidentialityRequirement, nil
	case "IR":
		return cvss20.IntegrityRequirement, nil
	case "AR":
		return cvss20.AvailabilityRequirement, nil
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
		cvss20.AccessVector = value
	case "AC":
		if err := validate(value, []string{"H", "M", "L"}); err != nil {
			return err
		}
		cvss20.AccessComplexity = value
	case "Au":
		if err := validate(value, []string{"M", "S", "N"}); err != nil {
			return err
		}
		cvss20.Authentication = value
	case "C":
		if err := validate(value, []string{"N", "P", "C"}); err != nil {
			return err
		}
		cvss20.ConfidentialityImpact = value
	case "I":
		if err := validate(value, []string{"N", "P", "C"}); err != nil {
			return err
		}
		cvss20.IntegrityImpact = value
	case "A":
		if err := validate(value, []string{"N", "P", "C"}); err != nil {
			return err
		}
		cvss20.AvailabilityImpact = value
	// Temporal
	case "E":
		if err := validate(value, []string{"U", "POC", "F", "H", "ND"}); err != nil {
			return err
		}
		cvss20.Exploitability = value
	case "RL":
		if err := validate(value, []string{"OF", "TF", "W", "U", "ND"}); err != nil {
			return err
		}
		cvss20.RemediationLevel = value
	case "RC":
		if err := validate(value, []string{"UC", "UR", "C", "ND"}); err != nil {
			return err
		}
		cvss20.ReportConfidence = value
	// Environmental
	case "CDP":
		if err := validate(value, []string{"N", "L", "LM", "MH", "H", "ND"}); err != nil {
			return err
		}
		cvss20.CollateralDamagePotential = value
	case "TD":
		if err := validate(value, []string{"N", "L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.TargetDistribution = value
	case "CR":
		if err := validate(value, []string{"L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.ConfidentialityRequirement = value
	case "IR":
		if err := validate(value, []string{"L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.IntegrityRequirement = value
	case "AR":
		if err := validate(value, []string{"L", "M", "H", "ND"}); err != nil {
			return err
		}
		cvss20.AvailabilityRequirement = value
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
	impact := 10.41 * (1 - (1-cia(cvss20.ConfidentialityImpact))*(1-cia(cvss20.IntegrityImpact))*(1-cia(cvss20.AvailabilityImpact)))
	fimpact := 0.0
	if impact != 0 {
		fimpact = 1.176
	}
	exploitability := 20 * accessVector(cvss20.AccessVector) * accessComplexity(cvss20.AccessComplexity) * authentication(cvss20.Authentication)
	return roundTo1Decimal(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fimpact)
}

// TemporalScore returns the CVSS v2.0's temporal score.
func (cvss20 CVSS20) TemporalScore() float64 {
	return roundTo1Decimal(cvss20.BaseScore() * exploitability(cvss20.Exploitability) * remediationLevel(cvss20.RemediationLevel) * reportConfidence(cvss20.ReportConfidence))
}

// EnvironmentalScore returns the CVSS v2.0's environmental score.
func (cvss20 CVSS20) EnvironmentalScore() float64 {
	// Recompute base score
	adjustedImpact := math.Min(10, 10.41*(1-(1-cia(cvss20.ConfidentialityImpact)*ciar(cvss20.ConfidentialityRequirement))*(1-cia(cvss20.IntegrityImpact)*ciar(cvss20.IntegrityRequirement))*(1-cia(cvss20.AvailabilityImpact)*ciar(cvss20.AvailabilityRequirement))))
	fimpactBase := 0.0
	if adjustedImpact != 0 {
		fimpactBase = 1.176
	}
	expltBase := 20 * accessVector(cvss20.AccessVector) * accessComplexity(cvss20.AccessComplexity) * authentication(cvss20.Authentication)
	recBase := roundTo1Decimal(((0.6 * adjustedImpact) + (0.4 * expltBase) - 1.5) * fimpactBase)
	adjustedTemporal := roundTo1Decimal(recBase * exploitability(cvss20.Exploitability) * remediationLevel(cvss20.RemediationLevel) * reportConfidence(cvss20.ReportConfidence))
	return roundTo1Decimal((adjustedTemporal + (10-adjustedTemporal)*collateralDamagePotential(cvss20.CollateralDamagePotential)) * targetDistribution(cvss20.TargetDistribution))
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
