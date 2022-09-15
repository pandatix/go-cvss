package gocvss30

import (
	"math"
	"strings"
	"unsafe"
)

// This file is based on https://www.first.org/cvss/v3.0/cvss-v30-specification_v1.9.pdf.

const (
	header = "CVSS:3.0/"
)

// ParseVector parses a given vector string, validates it
// and returns a CVSS30.
func ParseVector(vector string) (*CVSS30, error) {
	// Check header
	if !strings.HasPrefix(vector, header) {
		return nil, ErrInvalidCVSSHeader
	}
	vector = vector[len(header):]

	// Work on each CVSS part
	cvss30 := &CVSS30{
		base: base{},
		temporal: temporal{
			exploitCodeMaturity: "X",
			remediationLevel:    "X",
			reportConfidence:    "X",
		},
		environmental: environmental{
			confidentialityRequirement: "X",
			integrityRequirement:       "X",
			availabilityRequirement:    "X",
			modifiedAttackVector:       "X",
			modifiedAttackComplexity:   "X",
			modifiedPrivilegesRequired: "X",
			modifiedUserInteraction:    "X",
			modifiedScope:              "X",
			modifiedConfidentiality:    "X",
			modifiedIntegrity:          "X",
			modifiedAvailability:       "X",
		},
	}

	kvm := kvm{}
	start := 0
	l := len(vector)
	for i := 0; i <= l; i++ {
		if i == l || vector[i] == '/' {
			a, v := splitCouple(vector[start:i])
			if err := kvm.Set(a); err != nil {
				return nil, err
			}
			if err := cvss30.Set(a, v); err != nil {
				return nil, err
			}
			start = i + 1
		}
	}

	// Check all base score metrics are defined
	if cvss30.attackVector == "" {
		return nil, &ErrMissing{Abv: "AV"}
	}
	if cvss30.attackComplexity == "" {
		return nil, &ErrMissing{Abv: "AC"}
	}
	if cvss30.privilegesRequired == "" {
		return nil, &ErrMissing{Abv: "PR"}
	}
	if cvss30.userInteraction == "" {
		return nil, &ErrMissing{Abv: "UI"}
	}
	if cvss30.scope == "" {
		return nil, &ErrMissing{Abv: "S"}
	}
	if cvss30.confidentiality == "" {
		return nil, &ErrMissing{Abv: "C"}
	}
	if cvss30.integrity == "" {
		return nil, &ErrMissing{Abv: "I"}
	}
	if cvss30.availability == "" {
		return nil, &ErrMissing{Abv: "A"}
	}

	return cvss30, nil
}

func splitCouple(couple string) (string, string) {
	for i := 0; i < len(couple); i++ {
		if couple[i] == ':' {
			return couple[:i], couple[i+1:]
		}
	}
	return couple, ""
}

// Vector returns the CVSS v3.1 vector string representation.
func (cvss30 CVSS30) Vector() string {
	l := lenVec(&cvss30)
	b := make([]byte, 0, l)
	b = append(b, header...)

	// Base
	mandatory(&b, "AV:", cvss30.attackVector)
	mandatory(&b, "/AC:", cvss30.attackComplexity)
	mandatory(&b, "/PR:", cvss30.privilegesRequired)
	mandatory(&b, "/UI:", cvss30.userInteraction)
	mandatory(&b, "/S:", cvss30.scope)
	mandatory(&b, "/C:", cvss30.confidentiality)
	mandatory(&b, "/I:", cvss30.integrity)
	mandatory(&b, "/A:", cvss30.availability)

	// Temporal
	notMandatory(&b, "/E:", cvss30.exploitCodeMaturity)
	notMandatory(&b, "/RL:", cvss30.remediationLevel)
	notMandatory(&b, "/RC:", cvss30.reportConfidence)

	// Environmental
	notMandatory(&b, "/CR:", cvss30.confidentialityRequirement)
	notMandatory(&b, "/IR:", cvss30.integrityRequirement)
	notMandatory(&b, "/AR:", cvss30.availabilityRequirement)
	notMandatory(&b, "/MAV:", cvss30.modifiedAttackVector)
	notMandatory(&b, "/MAC:", cvss30.modifiedAttackComplexity)
	notMandatory(&b, "/MPR:", cvss30.modifiedPrivilegesRequired)
	notMandatory(&b, "/MUI:", cvss30.modifiedUserInteraction)
	notMandatory(&b, "/MS:", cvss30.modifiedScope)
	notMandatory(&b, "/MC:", cvss30.modifiedConfidentiality)
	notMandatory(&b, "/MI:", cvss30.modifiedIntegrity)
	notMandatory(&b, "/MA:", cvss30.modifiedAvailability)

	return *(*string)(unsafe.Pointer(&b))
}

func lenVec(cvss30 *CVSS30) int {
	// Header: constant, so fixed (9)
	// Base:
	// - AV, AC, PR, UI: 4
	// - S, C, I, A: 3
	// - separators: 7
	// Total: 4*4 + 4*3 + 7 = 35
	l := len(header) + 35

	// Temporal:
	// - E: 3
	// - RL, RC: 4
	// - each one adds a separator
	if cvss30.exploitCodeMaturity != "X" {
		l += 4
	}
	if cvss30.remediationLevel != "X" {
		l += 5
	}
	if cvss30.reportConfidence != "X" {
		l += 5
	}

	// Environmental
	// - CR, IR, AR, MS, MC, MI, MA: 4
	// - MAV, MAC, MPR, MUI: 5
	// - each one adds a separator
	if cvss30.confidentialityRequirement != "X" {
		l += 5
	}
	if cvss30.integrityRequirement != "X" {
		l += 5
	}
	if cvss30.availabilityRequirement != "X" {
		l += 5
	}
	if cvss30.modifiedScope != "X" {
		l += 5
	}
	if cvss30.modifiedConfidentiality != "X" {
		l += 5
	}
	if cvss30.modifiedIntegrity != "X" {
		l += 5
	}
	if cvss30.modifiedAvailability != "X" {
		l += 5
	}
	if cvss30.modifiedAttackVector != "X" {
		l += 6
	}
	if cvss30.modifiedAttackComplexity != "X" {
		l += 6
	}
	if cvss30.modifiedPrivilegesRequired != "X" {
		l += 6
	}
	if cvss30.modifiedUserInteraction != "X" {
		l += 6
	}

	return l
}

func mandatory(b *[]byte, pre, v string) {
	*b = append(*b, pre...)
	*b = append(*b, v...)
}

func notMandatory(b *[]byte, pre, v string) {
	if v == "X" {
		return
	}
	mandatory(b, pre, v)
}

// CVSS30 embeds all the metric values defined by the CVSS v3.0
// specification.
// Attributes values must not be manipulated directly. Use Get
// and Set methods.
type CVSS30 struct {
	base
	temporal
	environmental
}

// base is the group of metrics defined with such name by the
// first.org CVSS v3.0 specification.
type base struct {
	// AV -> [N,A,L,P]. Mandatory
	attackVector string
	// AC -> [L,H]. Mandatory
	attackComplexity string
	// PR -> [N,L,H]. Mandatory
	privilegesRequired string
	// UI -> [N,R]. Mandatory
	userInteraction string
	// S -> [U,C]. Mandatory
	scope string
	// C -> [H,L,N]. Mandatory
	confidentiality string
	// I -> [H,L,N]. Mandatory
	integrity string
	// A -> [H,L,N]. Mandatory
	availability string
}

// temporal is the group of metrics defined with such name by the
// first.org CVSS v3.0 specification.
type temporal struct {
	// E -> [X,H,F,P,U]. Not mandatory
	exploitCodeMaturity string
	// RL -> [X,U,W,T,O]. Not mandatory
	remediationLevel string
	// RC -> [X,C,R,U]. Not mandatory
	reportConfidence string
}

// environmental is the group of metrics defined with such name by the
// first.org CVSS v3.0 specification.
type environmental struct {
	// CR -> [X,H,M,L]. Not mandatory
	confidentialityRequirement string
	// IR -> [X,H,M,L]. Not mandatory
	integrityRequirement string
	// AR -> [X,H,M,L]. Not mandatory
	availabilityRequirement string
	// MAV -> [X,N,A,L,P]. Not mandatory
	modifiedAttackVector string
	// MAC -> [X,L,H]. Not mandatory
	modifiedAttackComplexity string
	// MPR -> [X,N,L,H]. Not mandatory
	modifiedPrivilegesRequired string
	// MUI -> [X,N,R]. Not mandatory
	modifiedUserInteraction string
	// MS -> [X,U,C]. Not mandatory
	modifiedScope string
	// MC -> [X,N,L,H]. Not mandatory
	modifiedConfidentiality string
	// MI -> [X,N,L,H]. Not mandatory
	modifiedIntegrity string
	// MA -> [X,N,L,H]. Not mandatory
	modifiedAvailability string
}

// Get returns the value of the given metric abbreviation.
func (cvss30 CVSS30) Get(abv string) (string, error) {
	switch abv {
	case "AV":
		return cvss30.attackVector, nil
	case "AC":
		return cvss30.attackComplexity, nil
	case "PR":
		return cvss30.privilegesRequired, nil
	case "UI":
		return cvss30.userInteraction, nil
	case "S":
		return cvss30.scope, nil
	case "C":
		return cvss30.confidentiality, nil
	case "I":
		return cvss30.integrity, nil
	case "A":
		return cvss30.availability, nil
	case "E":
		return cvss30.exploitCodeMaturity, nil
	case "RL":
		return cvss30.remediationLevel, nil
	case "RC":
		return cvss30.reportConfidence, nil
	case "CR":
		return cvss30.confidentialityRequirement, nil
	case "IR":
		return cvss30.integrityRequirement, nil
	case "AR":
		return cvss30.availabilityRequirement, nil
	case "MAV":
		return cvss30.modifiedAttackVector, nil
	case "MAC":
		return cvss30.modifiedAttackComplexity, nil
	case "MPR":
		return cvss30.modifiedPrivilegesRequired, nil
	case "MUI":
		return cvss30.modifiedUserInteraction, nil
	case "MS":
		return cvss30.modifiedScope, nil
	case "MC":
		return cvss30.modifiedConfidentiality, nil
	case "MI":
		return cvss30.modifiedIntegrity, nil
	case "MA":
		return cvss30.modifiedAvailability, nil
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
		cvss30.attackVector = value
	case "AC":
		if err := validate(value, []string{"L", "H"}); err != nil {
			return err
		}
		cvss30.attackComplexity = value
	case "PR":
		if err := validate(value, []string{"N", "L", "H"}); err != nil {
			return err
		}
		cvss30.privilegesRequired = value
	case "UI":
		if err := validate(value, []string{"N", "R"}); err != nil {
			return err
		}
		cvss30.userInteraction = value
	case "S":
		if err := validate(value, []string{"U", "C"}); err != nil {
			return err
		}
		cvss30.scope = value
	case "C":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss30.confidentiality = value
	case "I":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss30.integrity = value
	case "A":
		if err := validate(value, []string{"H", "L", "N"}); err != nil {
			return err
		}
		cvss30.availability = value
	// Temporal
	case "E":
		if err := validate(value, []string{"X", "H", "F", "P", "U"}); err != nil {
			return err
		}
		cvss30.exploitCodeMaturity = value
	case "RL":
		if err := validate(value, []string{"X", "U", "W", "T", "O"}); err != nil {
			return err
		}
		cvss30.remediationLevel = value
	case "RC":
		if err := validate(value, []string{"X", "C", "R", "U"}); err != nil {
			return err
		}
		cvss30.reportConfidence = value
	// Environmental
	case "CR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss30.confidentialityRequirement = value
	case "IR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss30.integrityRequirement = value
	case "AR":
		if err := validate(value, []string{"X", "H", "M", "L"}); err != nil {
			return err
		}
		cvss30.availabilityRequirement = value
	case "MAV":
		if err := validate(value, []string{"X", "N", "A", "L", "P"}); err != nil {
			return err
		}
		cvss30.modifiedAttackVector = value
	case "MAC":
		if err := validate(value, []string{"X", "L", "H"}); err != nil {
			return err
		}
		cvss30.modifiedAttackComplexity = value
	case "MPR":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.modifiedPrivilegesRequired = value
	case "MUI":
		if err := validate(value, []string{"X", "N", "R"}); err != nil {
			return err
		}
		cvss30.modifiedUserInteraction = value
	case "MS":
		if err := validate(value, []string{"X", "U", "C"}); err != nil {
			return err
		}
		cvss30.modifiedScope = value
	case "MC":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.modifiedConfidentiality = value
	case "MI":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.modifiedIntegrity = value
	case "MA":
		if err := validate(value, []string{"X", "N", "L", "H"}); err != nil {
			return err
		}
		cvss30.modifiedAvailability = value
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
	impact := cvss30.Impact()
	exploitability := cvss30.Exploitability()
	if impact <= 0 {
		return 0
	}
	if cvss30.scope == "U" {
		return roundup(math.Min(impact+exploitability, 10))
	}
	return roundup(math.Min(1.08*(impact+exploitability), 10))
}

func (cvss30 CVSS30) Impact() float64 {
	isc := 1 - ((1 - cia(cvss30.confidentiality)) * (1 - cia(cvss30.integrity)) * (1 - cia(cvss30.availability)))
	if cvss30.scope == "U" {
		return 6.42 * isc
	} else {
		return 7.52*(isc-0.029) - 3.25*math.Pow(isc-0.02, 15)
	}
}

func (cvss30 CVSS30) Exploitability() float64 {
	return 8.22 * attackVector(cvss30.attackVector) * attackComplexity(cvss30.attackComplexity) * privilegesRequired(cvss30.privilegesRequired, cvss30.scope) * userInteraction(cvss30.userInteraction)
}

// TemporalScore returns the CVSS v3.0's temporal score.
func (cvss30 CVSS30) TemporalScore() float64 {
	return roundup(cvss30.BaseScore() * exploitCodeMaturity(cvss30.exploitCodeMaturity) * remediationLevel(cvss30.remediationLevel) * reportConfidence(cvss30.reportConfidence))
}

// EnvironmentalScore returns the CVSS v3.0's environmental score.
func (cvss30 CVSS30) EnvironmentalScore() float64 {
	// Choose which to use (use base if modified is not defined).
	// It is based on first.org online calculator's source code,
	// while it is not explicit in the specification which value
	// to use.
	mav := mod(cvss30.attackVector, cvss30.modifiedAttackVector)
	mac := mod(cvss30.attackComplexity, cvss30.modifiedAttackComplexity)
	mpr := mod(cvss30.privilegesRequired, cvss30.modifiedPrivilegesRequired)
	mui := mod(cvss30.userInteraction, cvss30.modifiedUserInteraction)
	ms := mod(cvss30.scope, cvss30.modifiedScope)
	mc := mod(cvss30.confidentiality, cvss30.modifiedConfidentiality)
	mi := mod(cvss30.integrity, cvss30.modifiedIntegrity)
	ma := mod(cvss30.availability, cvss30.modifiedAvailability)

	misc := math.Min(1-(1-ciar(cvss30.confidentialityRequirement)*cia(mc))*(1-ciar(cvss30.integrityRequirement)*cia(mi))*(1-ciar(cvss30.availabilityRequirement)*cia(ma)), 0.915)
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
		return roundup(roundup(math.Min(modifiedImpact+modifiedExploitability, 10)) * exploitCodeMaturity(cvss30.exploitCodeMaturity) * remediationLevel(cvss30.remediationLevel) * reportConfidence(cvss30.reportConfidence))
	}
	r := math.Min(1.08*(modifiedImpact+modifiedExploitability), 10)
	return roundup(roundup(r) * exploitCodeMaturity(cvss30.exploitCodeMaturity) * remediationLevel(cvss30.remediationLevel) * reportConfidence(cvss30.reportConfidence))
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

// kvm stands for Key-Value Map, and is used to make sure each
// metric is defined only once, as documented by the CVSS v3.1
// specification document, section 6 "Vector String" paragraph 3.
// Using this avoids a map that escapes to heap for each call of
// ParseVector, as its size is known and wont evolve.
type kvm struct {
	// base metrics
	av, ac, pr, ui, s, c, i, a bool
	// temporal metrics
	e, rl, rc bool
	// environmental metrics
	cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma bool
}

func (kvm *kvm) Set(abv string) error {
	var dst *bool
	switch abv {
	case "AV":
		dst = &kvm.av
	case "AC":
		dst = &kvm.ac
	case "PR":
		dst = &kvm.pr
	case "UI":
		dst = &kvm.ui
	case "S":
		dst = &kvm.s
	case "C":
		dst = &kvm.c
	case "I":
		dst = &kvm.i
	case "A":
		dst = &kvm.a
	case "E":
		dst = &kvm.e
	case "RL":
		dst = &kvm.rl
	case "RC":
		dst = &kvm.rc
	case "CR":
		dst = &kvm.cr
	case "IR":
		dst = &kvm.ir
	case "AR":
		dst = &kvm.ar
	case "MAV":
		dst = &kvm.mav
	case "MAC":
		dst = &kvm.mac
	case "MPR":
		dst = &kvm.mpr
	case "MUI":
		dst = &kvm.mui
	case "MS":
		dst = &kvm.ms
	case "MC":
		dst = &kvm.mc
	case "MI":
		dst = &kvm.mi
	case "MA":
		dst = &kvm.ma
	default:
		return &ErrInvalidMetric{Abv: abv}
	}
	if *dst {
		return &ErrDefinedN{Abv: abv}
	}
	*dst = true
	return nil
}
