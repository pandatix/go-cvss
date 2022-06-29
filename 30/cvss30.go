package gocvss30

import (
	"math"
	"strings"
)

// This file is based on https://www.first.org/cvss/v3.0/cvss-v30-specification_v1.9.pdf.

const (
	label = "CVSS:"
)

// ParseVector parses a given vector string, validates it
// and returns a CVSS30.
func ParseVector(vector string) (*CVSS30, error) {
	// Check label is present
	if len(vector) < len(label) {
		return nil, ErrTooShortVector
	}
	if vector[:len(label)] != label {
		return nil, ErrInvalidCVSSHeader
	}
	vector = vector[len(label):]

	// Split parts
	pts := strings.Split(vector, "/")
	if len(pts) < 8 {
		// 1 (version) + 7 (base score metrics)
		return nil, ErrTooShortVector
	}
	if pts[0] != "3.0" {
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
	cvss30 := &CVSS30{
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
		if err := cvss30.Set(abv, v); err != nil {
			return nil, err
		}
	}

	// Check all base score metrics are defined
	errs := &ErrBaseScore{}
	if cvss30.Base.AttackVector == "" {
		errs.Missings = append(errs.Missings, "AV")
	}
	if cvss30.Base.AttackComplexity == "" {
		errs.Missings = append(errs.Missings, "AC")
	}
	if cvss30.Base.PrivilegesRequired == "" {
		errs.Missings = append(errs.Missings, "PR")
	}
	if cvss30.Base.UserInteraction == "" {
		errs.Missings = append(errs.Missings, "UI")
	}
	if cvss30.Base.Scope == "" {
		errs.Missings = append(errs.Missings, "S")
	}
	if cvss30.Base.Confidentiality == "" {
		errs.Missings = append(errs.Missings, "C")
	}
	if cvss30.Base.Integrity == "" {
		errs.Missings = append(errs.Missings, "I")
	}
	if cvss30.Base.Availability == "" {
		errs.Missings = append(errs.Missings, "A")
	}
	if len(errs.Missings) != 0 {
		return nil, errs
	}

	return cvss30, nil
}

// Vector returns the CVSS v3.0 vector string representation.
func (cvss30 CVSS30) Vector() string {
	s := label + "3.0"
	// Base
	s += "/AV:" + cvss30.AttackVector
	s += "/AC:" + cvss30.AttackComplexity
	s += "/PR:" + cvss30.PrivilegesRequired
	s += "/UI:" + cvss30.UserInteraction
	s += "/S:" + cvss30.Scope
	s += "/C:" + cvss30.Confidentiality
	s += "/I:" + cvss30.Integrity
	s += "/A:" + cvss30.Availability
	// Temporal
	s += notMandatory("E", cvss30.ExploitCodeMaturity)
	s += notMandatory("RL", cvss30.RemediationLevel)
	s += notMandatory("RC", cvss30.ReportConfidence)
	// Environmental
	s += notMandatory("CR", cvss30.ConfidentialityRequirement)
	s += notMandatory("IR", cvss30.IntegrityRequirement)
	s += notMandatory("AR", cvss30.AvailabilityRequirement)
	s += notMandatory("MAV", cvss30.ModifiedAttackVector)
	s += notMandatory("MAC", cvss30.ModifiedAttackComplexity)
	s += notMandatory("MPR", cvss30.ModifiedPrivilegesRequired)
	s += notMandatory("MUI", cvss30.ModifiedUserInteraction)
	s += notMandatory("MS", cvss30.ModifiedScope)
	s += notMandatory("MC", cvss30.ModifiedConfidentiality)
	s += notMandatory("MI", cvss30.ModifiedIntegrity)
	s += notMandatory("MA", cvss30.ModifiedAvailability)
	return s
}

func notMandatory(abv, v string) string {
	if v == "X" {
		return ""
	}
	return "/" + abv + ":" + v
}

// CVSS30 embeds all the metric values defined by the CVSS v3.0
// specification.
// Attributes values must not be manipulated directly. Use Get
// and Set methods.
type CVSS30 struct {
	Base
	Temporal
	Environmental
}

// Base is the group of metrics defined with such name by the
// first.org CVSS v3.0 specification.
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
// first.org CVSS v3.0 specification.
type Temporal struct {
	// E -> [X,H,F,P,U]. Not mandatory
	ExploitCodeMaturity string
	// RL -> [X,U,W,T,O]. Not mandatory
	RemediationLevel string
	// RC -> [X,C,R,U]. Not mandatory
	ReportConfidence string
}

// Environmental is the group of metrics defined with such name by the
// first.org CVSS v3.0 specification.
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
func (cvss30 CVSS30) Get(abv string) (string, error) {
	switch abv {
	case "AV":
		return cvss30.AttackVector, nil
	case "AC":
		return cvss30.AttackComplexity, nil
	case "PR":
		return cvss30.PrivilegesRequired, nil
	case "UI":
		return cvss30.UserInteraction, nil
	case "S":
		return cvss30.Scope, nil
	case "C":
		return cvss30.Confidentiality, nil
	case "I":
		return cvss30.Integrity, nil
	case "A":
		return cvss30.Availability, nil
	case "E":
		return cvss30.ExploitCodeMaturity, nil
	case "RL":
		return cvss30.RemediationLevel, nil
	case "RC":
		return cvss30.ReportConfidence, nil
	case "CR":
		return cvss30.ConfidentialityRequirement, nil
	case "IR":
		return cvss30.IntegrityRequirement, nil
	case "AR":
		return cvss30.AvailabilityRequirement, nil
	case "MAV":
		return cvss30.ModifiedAttackVector, nil
	case "MAC":
		return cvss30.ModifiedAttackComplexity, nil
	case "MPR":
		return cvss30.ModifiedPrivilegesRequired, nil
	case "MUI":
		return cvss30.ModifiedUserInteraction, nil
	case "MS":
		return cvss30.ModifiedScope, nil
	case "MC":
		return cvss30.ModifiedConfidentiality, nil
	case "MI":
		return cvss30.ModifiedIntegrity, nil
	case "MA":
		return cvss30.ModifiedAvailability, nil
	default:
		return "", &ErrInvalidMetric{Abv: abv}
	}
}

// Set sets the value of the given metric abbreviation.
func (cvss30 *CVSS30) Set(abv string, value string) error {
	switch abv {
	// Base
	case "AV":
		if err := validate(value, []string{"N", "A", "L", "P"}); err != nil {
			return err
		}
		cvss30.AttackVector = value
	case "AC":
		if err := validate(value, []string{"L", "H"}); err != nil {
			return err
		}
		cvss30.AttackComplexity = value
	case "PR":
		if err := validate(value, []string{"N", "L", "H"}); err != nil {
			return err
		}
		cvss30.PrivilegesRequired = value
	case "UI":
		if err := validate(value, []string{"N", "R"}); err != nil {
			return err
		}
		cvss30.UserInteraction = value
	case "S":
		if err := validate(value, []string{"U", "C"}); err != nil {
			return err
		}
		cvss30.Scope = value
	case "C":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss30.Confidentiality = value
	case "I":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss30.Integrity = value
	case "A":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss30.Availability = value
	// Temporal
	case "E":
		if err := validate(value, []string{"X", "H", "F", "P", "U"}); err != nil {
			return err
		}
		cvss30.ExploitCodeMaturity = value
	case "RL":
		if err := validate(value, []string{"X", "U", "W", "T", "O"}); err != nil {
			return err
		}
		cvss30.RemediationLevel = value
	case "RC":
		if err := validate(value, []string{"X", "C", "R", "U"}); err != nil {
			return err
		}
		cvss30.ReportConfidence = value
	// Environmental
	case "CR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss30.ConfidentialityRequirement = value
	case "IR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss30.IntegrityRequirement = value
	case "AR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss30.AvailabilityRequirement = value
	case "MAV":
		if err := validate(value, []string{"X", "N", "A", "L", "P"}); err != nil {
			return err
		}
		cvss30.ModifiedAttackVector = value
	case "MAC":
		if err := validate(value, []string{"X", "L", "H"}); err != nil {
			return err
		}
		cvss30.ModifiedAttackComplexity = value
	case "MPR":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.ModifiedPrivilegesRequired = value
	case "MUI":
		if err := validate(value, []string{"X", "N", "R"}); err != nil {
			return err
		}
		cvss30.ModifiedUserInteraction = value
	case "MS":
		if err := validate(value, []string{"X", "U", "C"}); err != nil {
			return err
		}
		cvss30.ModifiedScope = value
	case "MC":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.ModifiedConfidentiality = value
	case "MI":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.ModifiedIntegrity = value
	case "MA":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.ModifiedAvailability = value
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

// BaseScore returns the CVSS v3.0's base score.
func (cvss30 CVSS30) BaseScore() float64 {
	isc := 1 - ((1 - cia(cvss30.Confidentiality)) * (1 - cia(cvss30.Integrity)) * (1 - cia(cvss30.Availability)))
	var impact float64
	if cvss30.Scope == "U" {
		impact = 6.42 * isc
	} else {
		impact = 7.52*(isc-0.029) - 3.25*math.Pow(isc-0.02, 15)
	}
	exploitability := 8.22 * attackVector(cvss30.AttackVector) * attackComplexity(cvss30.AttackComplexity) * privilegesRequired(cvss30.PrivilegesRequired, cvss30.Scope) * userInteraction(cvss30.UserInteraction)
	if impact <= 0 {
		return 0
	}
	if cvss30.Scope == "U" {
		return roundup(math.Min(impact+exploitability, 10))
	}
	return roundup(math.Min(1.08*(impact+exploitability), 10))
}

// TemporalScore returns the CVSS v3.0's temporal score.
func (cvss30 CVSS30) TemporalScore() float64 {
	return roundup(cvss30.BaseScore() * exploitCodeMaturity(cvss30.ExploitCodeMaturity) * remediationLevel(cvss30.RemediationLevel) * reportConfidence(cvss30.ReportConfidence))
}

// EnvironmentalScore returns the CVSS v3.0's environmental score.
func (cvss30 CVSS30) EnvironmentalScore() float64 {
	// Choose which to use (use base if modified is not defined).
	// It is based on first.org online calculator's source code,
	// while it is not explicit in the specification which value
	// to use.
	mav := mod(cvss30.AttackVector, cvss30.ModifiedAttackVector)
	mac := mod(cvss30.AttackComplexity, cvss30.ModifiedAttackComplexity)
	mpr := mod(cvss30.PrivilegesRequired, cvss30.ModifiedPrivilegesRequired)
	mui := mod(cvss30.UserInteraction, cvss30.ModifiedUserInteraction)
	ms := mod(cvss30.Scope, cvss30.ModifiedScope)
	mc := mod(cvss30.Confidentiality, cvss30.ModifiedConfidentiality)
	mi := mod(cvss30.Integrity, cvss30.ModifiedIntegrity)
	ma := mod(cvss30.Availability, cvss30.ModifiedAvailability)

	misc := math.Min(1-(1-ciar(cvss30.ConfidentialityRequirement)*cia(mc))*(1-ciar(cvss30.IntegrityRequirement)*cia(mi))*(1-ciar(cvss30.AvailabilityRequirement)*cia(ma)), 0.915)
	var modifiedImpact float64
	if ms == "U" {
		modifiedImpact = 6.42 * misc
	} else {
		modifiedImpact = 7.52*(misc-0.029) - 3.25*math.Pow(misc-0.02, 15)
	}
	modifiedExploitability := 8.22 * attackVector(mav) * attackComplexity(mac) * privilegesRequired(mpr, ms) * userInteraction(mui)
	if modifiedImpact <= 0 {
		return 0
	}
	if ms == "U" {
		return roundup(roundup(math.Min(modifiedImpact+modifiedExploitability, 10)) * exploitCodeMaturity(cvss30.ExploitCodeMaturity) * remediationLevel(cvss30.RemediationLevel) * reportConfidence(cvss30.ReportConfidence))
	}
	r := math.Min(1.08*(modifiedImpact+modifiedExploitability), 10)
	return roundup(roundup(r) * exploitCodeMaturity(cvss30.ExploitCodeMaturity) * remediationLevel(cvss30.RemediationLevel) * reportConfidence(cvss30.ReportConfidence))
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

// Helpers to compute CVSS v3.0 scores

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
