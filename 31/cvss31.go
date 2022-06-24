package gocvss31

import (
	"math"
	"strings"
)

// This file is based on https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf.

const (
	label = "CVSS:"
)

// ParseVector parses a given vector string, validates it
// and returns a CVSS31.
func ParseVector(vector string) (*CVSS31, error) {
	// Check label is present
	if len(vector) < len(label) {
		return nil, ErrTooShortVector
	}
	vector = vector[len(label):]

	// Split parts
	pts := strings.Split(vector, "/")
	if len(pts) < 8 {
		// 1 (version) + 7 (base score metrics)
		return nil, ErrTooShortVector
	}
	if pts[0] != "3.1" {
		return nil, ErrInvalidCVSSVersion
	}
	pts = pts[1:]

	// Check each metric is set only once
	kvm := map[string]string{}
	errn := &ErrDefinedN{}
	for _, pt := range pts {
		abv, v, _ := strings.Cut(pt, ":")
		if _, ok := kvm[abv]; ok {
			errn.Abv = append(errn.Abv, abv)
		}
		kvm[abv] = v
	}
	if len(errn.Abv) != 0 {
		return nil, errn
	}

	// Work on each CVSS part
	cvss31 := &CVSS31{
		Base: Base{},
		Temporal: Temporal{
			ExploitCodeMaturity: "X",
			RemediationLevel:    "X",
			ReportConfidence:    "X",
		},
		Environmental: Environmental{
			ConfidentialityRequirement: "X",
			IntegrityRequirement:       "X",
			AvailabilityRequirement:    "X",
			ModifiedAttackVector:       "X",
			ModifiedAttackComplexity:   "X",
			ModifiedPrivilegesRequired: "X",
			ModifiedUserInteraction:    "X",
			ModifiedScope:              "X",
			ModifiedConfidentiality:    "X",
			ModifiedIntegrity:          "X",
			ModifiedAvailability:       "X",
		},
	}
	for abv, v := range kvm {
		if err := cvss31.Set(abv, v); err != nil {
			return nil, err
		}
	}

	// Check all base score metrics are defined
	errs := &ErrBaseScore{}
	if cvss31.Base.AttackVector == "" {
		errs.Missings = append(errs.Missings, "AV")
	}
	if cvss31.Base.AttackComplexity == "" {
		errs.Missings = append(errs.Missings, "AC")
	}
	if cvss31.Base.PrivilegesRequired == "" {
		errs.Missings = append(errs.Missings, "PR")
	}
	if cvss31.Base.UserInteraction == "" {
		errs.Missings = append(errs.Missings, "UI")
	}
	if cvss31.Base.Scope == "" {
		errs.Missings = append(errs.Missings, "S")
	}
	if cvss31.Base.Confidentiality == "" {
		errs.Missings = append(errs.Missings, "C")
	}
	if cvss31.Base.Integrity == "" {
		errs.Missings = append(errs.Missings, "I")
	}
	if cvss31.Base.Availability == "" {
		errs.Missings = append(errs.Missings, "A")
	}
	if len(errs.Missings) != 0 {
		return nil, errs
	}

	return cvss31, nil
}

// Vector returns the CVSS v3.1 vector string representation.
func (cvss31 CVSS31) Vector() string {
	s := label + "3.1:"
	// Base
	s += "/AV:" + cvss31.AttackVector
	s += "/AC:" + cvss31.AttackComplexity
	s += "/PR:" + cvss31.PrivilegesRequired
	s += "/UI:" + cvss31.UserInteraction
	s += "/S:" + cvss31.Scope
	s += "/C:" + cvss31.Confidentiality
	s += "/I:" + cvss31.Integrity
	s += "/A:" + cvss31.Availability
	// Temporal
	s += notMandatory("E", cvss31.ExploitCodeMaturity)
	s += notMandatory("RL", cvss31.RemediationLevel)
	s += notMandatory("RC", cvss31.ReportConfidence)
	// Environmental
	s += notMandatory("CR", cvss31.ConfidentialityRequirement)
	s += notMandatory("IR", cvss31.IntegrityRequirement)
	s += notMandatory("AR", cvss31.AvailabilityRequirement)
	s += notMandatory("MAV", cvss31.ModifiedAttackVector)
	s += notMandatory("MAC", cvss31.ModifiedAttackComplexity)
	s += notMandatory("MPR", cvss31.ModifiedPrivilegesRequired)
	s += notMandatory("MUI", cvss31.ModifiedUserInteraction)
	s += notMandatory("MS", cvss31.ModifiedScope)
	s += notMandatory("MC", cvss31.ModifiedConfidentiality)
	s += notMandatory("MI", cvss31.ModifiedIntegrity)
	s += notMandatory("MA", cvss31.ModifiedAvailability)
	return s
}

func notMandatory(abv, v string) string {
	if v == "X" {
		return ""
	}
	return "/" + abv + ":" + v
}

// CVSS31 embeds all the metric values defined by the CVSS v3.1
// specification.
// Attributes values must not be manipulated directly. Use Get
// and Set methods.
type CVSS31 struct {
	Base
	Temporal
	Environmental
}

// Base is the group of metrics defined with such name by the
// first.org CVSS v3.1 specification.
type Base struct {
	// AV -> [N,A,L,P]. Mandatory
	AttackVector string
	// AC -> [L,H]. Mandatory
	AttackComplexity string
	// PR -> [N,L,H]. Mandatory
	PrivilegesRequired string
	// UI -> [N,R]. Mandatory
	UserInteraction string
	// S -> [U,C]. Mandatory
	Scope string
	// C -> [H,L,N]. Mandatory
	Confidentiality string
	// I -> [H,L,N]. Mandatory
	Integrity string
	// A -> [H,L,N]. Mandatory
	Availability string
}

// Temporal is the group of metrics defined with such name by the
// first.org CVSS v3.1 specification.
type Temporal struct {
	// E -> [X,H,F,P,U]. Not mandatory
	ExploitCodeMaturity string
	// RL -> [X,U,W,T,O]. Not mandatory
	RemediationLevel string
	// RC -> [X,C,R,U]. Not mandatory
	ReportConfidence string
}

// Environmental is the group of metrics defined with such name by the
// first.org CVSS v3.1 specification.
type Environmental struct {
	// CR -> [X,H,M,L]. Not mandatory
	ConfidentialityRequirement string
	// IR -> [X,H,M,L]. Not mandatory
	IntegrityRequirement string
	// AR -> [X,H,M,L]. Not mandatory
	AvailabilityRequirement string
	// MAV -> [X,N,A,L,P]. Not mandatory
	ModifiedAttackVector string
	// MAC -> [X,L,H]. Not mandatory
	ModifiedAttackComplexity string
	// MPR -> [X,N,L,H]. Not mandatory
	ModifiedPrivilegesRequired string
	// MUI -> [X,N,R]. Not mandatory
	ModifiedUserInteraction string
	// MS -> [X,U,C]. Not mandatory
	ModifiedScope string
	// MC -> [X,N,L,H]. Not mandatory
	ModifiedConfidentiality string
	// MI -> [X,N,L,H]. Not mandatory
	ModifiedIntegrity string
	// MA -> [X,N,L,H]. Not mandatory
	ModifiedAvailability string
}

// Get returns the value of the given metric abbreviation.
func (cvss31 CVSS31) Get(abv string) (any, error) {
	switch abv {
	case "AV":
		return cvss31.AttackVector, nil
	case "AC":
		return cvss31.AttackComplexity, nil
	case "PR":
		return cvss31.PrivilegesRequired, nil
	case "UI":
		return cvss31.UserInteraction, nil
	case "S":
		return cvss31.Scope, nil
	case "C":
		return cvss31.Confidentiality, nil
	case "I":
		return cvss31.Integrity, nil
	case "A":
		return cvss31.Availability, nil
	case "E":
		return cvss31.ExploitCodeMaturity, nil
	case "RL":
		return cvss31.RemediationLevel, nil
	case "RC":
		return cvss31.ReportConfidence, nil
	case "CR":
		return cvss31.ConfidentialityRequirement, nil
	case "IR":
		return cvss31.IntegrityRequirement, nil
	case "AR":
		return cvss31.AvailabilityRequirement, nil
	case "MAV":
		return cvss31.ModifiedAttackVector, nil
	case "MAC":
		return cvss31.ModifiedAttackComplexity, nil
	case "MPR":
		return cvss31.ModifiedPrivilegesRequired, nil
	case "MUI":
		return cvss31.ModifiedUserInteraction, nil
	case "MS":
		return cvss31.ModifiedScope, nil
	case "MC":
		return cvss31.ModifiedConfidentiality, nil
	case "MI":
		return cvss31.ModifiedIntegrity, nil
	case "MA":
		return cvss31.ModifiedAvailability, nil
	default:
		return nil, &ErrInvalidMetric{Abv: abv}
	}
}

// Set sets the value of the given metric abbreviation.
func (cvss31 *CVSS31) Set(abv string, value string) error {
	switch abv {
	// Base
	case "AV":
		if err := validate(value, []string{"N", "A", "L", "P"}); err != nil {
			return err
		}
		cvss31.AttackVector = value
	case "AC":
		if err := validate(value, []string{"L", "H"}); err != nil {
			return err
		}
		cvss31.AttackComplexity = value
	case "PR":
		if err := validate(value, []string{"N", "L", "H"}); err != nil {
			return err
		}
		cvss31.PrivilegesRequired = value
	case "UI":
		if err := validate(value, []string{"N", "R"}); err != nil {
			return err
		}
		cvss31.UserInteraction = value
	case "S":
		if err := validate(value, []string{"U", "C"}); err != nil {
			return err
		}
		cvss31.Scope = value
	case "C":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss31.Confidentiality = value
	case "I":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss31.Integrity = value
	case "A":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss31.Availability = value
	// Temporal
	case "E":
		if err := validate(value, []string{"X", "H", "F", "P", "U"}); err != nil {
			return err
		}
		cvss31.ExploitCodeMaturity = value
	case "RL":
		if err := validate(value, []string{"X", "U", "W", "T", "O"}); err != nil {
			return err
		}
		cvss31.RemediationLevel = value
	case "RC":
		if err := validate(value, []string{"X", "C", "R", "U"}); err != nil {
			return err
		}
		cvss31.ReportConfidence = value
	// Environmental
	case "CR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss31.ConfidentialityRequirement = value
	case "IR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss31.IntegrityRequirement = value
	case "AR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss31.AvailabilityRequirement = value
	case "MAV":
		if err := validate(value, []string{"X", "N", "A", "L", "P"}); err != nil {
			return err
		}
		cvss31.ModifiedAttackVector = value
	case "MAC":
		if err := validate(value, []string{"X", "L", "H"}); err != nil {
			return err
		}
		cvss31.ModifiedAttackComplexity = value
	case "MPR":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss31.ModifiedPrivilegesRequired = value
	case "MUI":
		if err := validate(value, []string{"X", "N", "R"}); err != nil {
			return err
		}
		cvss31.ModifiedUserInteraction = value
	case "MS":
		if err := validate(value, []string{"X", "U", "C"}); err != nil {
			return err
		}
		cvss31.ModifiedScope = value
	case "MC":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss31.ModifiedConfidentiality = value
	case "MI":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss31.ModifiedIntegrity = value
	case "MA":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss31.ModifiedAvailability = value
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

// BaseScore returns the CVSS v3.1's base score.
func (cvss31 CVSS31) BaseScore() float64 {
	iss := 1 - ((1 - cia(cvss31.Confidentiality)) * (1 - cia(cvss31.Integrity)) * (1 - cia(cvss31.Availability)))
	var impact float64
	if cvss31.Scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * attackVector(cvss31.AttackVector) * attackComplexity(cvss31.AttackComplexity) * privilegesRequired(cvss31.PrivilegesRequired, cvss31.Scope) * userInteraction(cvss31.UserInteraction)
	if impact <= 0 {
		return 0
	}
	if cvss31.Scope == "U" {
		return roundup(math.Min(impact+exploitability, 10))
	}
	return roundup(math.Min(1.08*(impact+exploitability), 10))
}

// TemporalScore returns the CVSS v3.1's temporal score.
func (cvss31 CVSS31) TemporalScore() float64 {
	return roundup(cvss31.BaseScore() * exploitCodeMaturity(cvss31.ExploitCodeMaturity) * remediationLevel(cvss31.RemediationLevel) * reportConfidence(cvss31.ReportConfidence))
}

// EnvironmentalScore returns the CVSS v3.1's environmental score.
func (cvss31 CVSS31) EnvironmentalScore() float64 {
	// Choose which to use (use base if modified is not defined).
	// It is based on first.org online calculator's source code,
	// while it is not explicit in the specification which value
	// to use.
	mav := mod(cvss31.AttackVector, cvss31.ModifiedAttackVector)
	mac := mod(cvss31.AttackComplexity, cvss31.ModifiedAttackComplexity)
	mpr := mod(cvss31.PrivilegesRequired, cvss31.ModifiedPrivilegesRequired)
	mui := mod(cvss31.UserInteraction, cvss31.ModifiedUserInteraction)
	ms := mod(cvss31.Scope, cvss31.ModifiedScope)
	mc := mod(cvss31.Confidentiality, cvss31.ModifiedConfidentiality)
	mi := mod(cvss31.Integrity, cvss31.ModifiedIntegrity)
	ma := mod(cvss31.Availability, cvss31.ModifiedAvailability)

	miss := math.Min(1-(1-ciar(cvss31.ConfidentialityRequirement)*cia(mc))*(1-ciar(cvss31.IntegrityRequirement)*cia(mi))*(1-ciar(cvss31.AvailabilityRequirement)*cia(ma)), 0.915)
	var modifiedImpact float64
	if ms == "U" {
		modifiedImpact = 6.42 * miss
	} else {
		modifiedImpact = 7.52*(miss-0.029) - 3.25*math.Pow(miss*0.9731-0.02, 13)
	}
	modifiedExploitability := 8.22 * attackVector(mav) * attackComplexity(mac) * privilegesRequired(mpr, ms) * userInteraction(mui)
	if modifiedImpact <= 0 {
		return 0
	}
	if ms == "U" {
		return roundup(roundup(math.Min(modifiedImpact+modifiedExploitability, 10)) * exploitCodeMaturity(cvss31.ExploitCodeMaturity) * remediationLevel(cvss31.RemediationLevel) * reportConfidence(cvss31.ReportConfidence))
	}
	r := math.Min(1.08*(modifiedImpact+modifiedExploitability), 10)
	return roundup(roundup(r) * exploitCodeMaturity(cvss31.ExploitCodeMaturity) * remediationLevel(cvss31.RemediationLevel) * reportConfidence(cvss31.ReportConfidence))
}

// Rating returns the verbose for a given rating.
// It does not check wether the number of decimal is valid,
// as it can differ due to binary imprecisions, and such
// behaviour is not enforced by the specification.
func Rating(score float64) (string, error) {
	if score < 0.0 || score > 10.0 {
		return "", ErrOutOfBoundsScore
	}
	if score >= 9.0 {
		return "CRITICAL", nil
	}
	if score >= 7.0 {
		return "HIGH", nil
	}
	if score >= 4.0 {
		return "MEDIUM", nil
	}
	if score >= 0.1 {
		return "LOW", nil
	}
	return "NONE", nil
}

// Helpers to compute CVSS v3.1 scores

func attackVector(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	case "P":
		return 0.2
	default:
		panic(ErrInvalidMetricValue)
	}
}

func attackComplexity(v string) float64 {
	switch v {
	case "L":
		return 0.77
	case "H":
		return 0.44
	default:
		panic(ErrInvalidMetricValue)
	}
}

func privilegesRequired(v, scope string) float64 {
	switch v {
	case "N":
		return 0.85
	case "L":
		if scope == "C" {
			return 0.68
		}
		return 0.62
	case "H":
		if scope == "C" {
			return 0.5
		}
		return 0.27
	default:
		panic(ErrInvalidMetricValue)
	}
}

func userInteraction(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "R":
		return 0.62
	default:
		panic(ErrInvalidMetricValue)
	}
}

func cia(v string) float64 {
	switch v {
	case "H":
		return 0.56
	case "L":
		return 0.22
	case "N":
		return 0
	default:
		panic(ErrInvalidMetricValue)
	}
}

func exploitCodeMaturity(v string) float64 {
	switch v {
	case "X":
		return 1
	case "H":
		return 1
	case "F":
		return 0.97
	case "P":
		return 0.94
	case "U":
		return 0.91
	default:
		panic(ErrInvalidMetricValue)
	}
}

func remediationLevel(v string) float64 {
	switch v {
	case "X":
		return 1
	case "U":
		return 1
	case "W":
		return 0.97
	case "T":
		return 0.96
	case "O":
		return 0.95
	default:
		panic(ErrInvalidMetricValue)
	}
}

func reportConfidence(v string) float64 {
	switch v {
	case "X":
		return 1
	case "C":
		return 1
	case "R":
		return 0.96
	case "U":
		return 0.92
	default:
		panic(ErrInvalidMetricValue)
	}
}

func ciar(v string) float64 {
	switch v {
	case "X":
		return 1
	case "H":
		return 1.5
	case "M":
		return 1
	case "L":
		return 0.5
	default:
		panic(ErrInvalidMetricValue)
	}
}

func roundup(x float64) float64 {
	bx := math.RoundToEven(x * 100000)
	if int(bx)%10000 == 0 {
		return bx / 100000.0
	}
	return (math.Floor(bx/10000) + 1) / 10.0
}

func mod(base, modified string) string {
	if modified != "X" {
		return modified
	}
	return base
}
