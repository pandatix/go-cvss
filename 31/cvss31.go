package gocvss31

import (
	"math"
	"strings"
	"unsafe"
)

// This file is based on https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf.

const (
	header = "CVSS:3.1/"
)

// ParseVector parses a given vector string, validates it
// and returns a CVSS31.
func ParseVector(vector string) (*CVSS31, error) {
	// Check header
	if !strings.HasPrefix(vector, header) {
		return nil, ErrInvalidCVSSHeader
	}
	vector = vector[len(header):]

	// Allocate CVSS v3.1 object
	cvss31 := &CVSS31{
		base: base{
			attackVector:       av_ndef,
			attackComplexity:   ac_ndef,
			privilegesRequired: pr_ndef,
			userInteraction:    ui_ndef,
			scope:              s_ndef,
			confidentiality:    cia_ndef,
			integrity:          cia_ndef,
			availability:       cia_ndef,
		},
		temporal: temporal{
			exploitCodeMaturity: e_x,
			remediationLevel:    rl_x,
			reportConfidence:    rc_x,
		},
		environmental: environmental{
			confidentialityRequirement: ciar_x,
			integrityRequirement:       ciar_x,
			availabilityRequirement:    ciar_x,
			modifiedAttackVector:       mav_x,
			modifiedAttackComplexity:   mac_x,
			modifiedPrivilegesRequired: mpr_x,
			modifiedUserInteraction:    mui_x,
			modifiedScope:              ms_x,
			modifiedConfidentiality:    mcia_x,
			modifiedIntegrity:          mcia_x,
			modifiedAvailability:       mcia_x,
		},
	}

	// Parse vector
	kvm := kvm{}
	start := 0
	l := len(vector)
	for i := 0; i <= l; i++ {
		if i == l || vector[i] == '/' {
			a, v := splitCouple(vector[start:i])
			if err := kvm.Set(a); err != nil {
				return nil, err
			}
			if err := cvss31.Set(a, v); err != nil {
				return nil, err
			}
			start = i + 1
		}
	}

	// Check all base score metrics are defined
	if cvss31.attackVector == av_ndef {
		return nil, &ErrMissing{Abv: "AV"}
	}
	if cvss31.attackComplexity == ac_ndef {
		return nil, &ErrMissing{Abv: "AC"}
	}
	if cvss31.privilegesRequired == pr_ndef {
		return nil, &ErrMissing{Abv: "PR"}
	}
	if cvss31.userInteraction == ui_ndef {
		return nil, &ErrMissing{Abv: "UI"}
	}
	if cvss31.scope == s_ndef {
		return nil, &ErrMissing{Abv: "S"}
	}
	if cvss31.confidentiality == cia_ndef {
		return nil, &ErrMissing{Abv: "C"}
	}
	if cvss31.integrity == cia_ndef {
		return nil, &ErrMissing{Abv: "I"}
	}
	if cvss31.availability == cia_ndef {
		return nil, &ErrMissing{Abv: "A"}
	}

	return cvss31, nil
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
func (cvss31 CVSS31) Vector() string {
	l := lenVec(&cvss31)
	b := make([]byte, 0, l)
	b = append(b, header...)

	// Base
	mandatory(&b, "AV:", must(cvss31.Get("AV")))
	mandatory(&b, "/AC:", must(cvss31.Get("AC")))
	mandatory(&b, "/PR:", must(cvss31.Get("PR")))
	mandatory(&b, "/UI:", must(cvss31.Get("UI")))
	mandatory(&b, "/S:", must(cvss31.Get("S")))
	mandatory(&b, "/C:", must(cvss31.Get("C")))
	mandatory(&b, "/I:", must(cvss31.Get("I")))
	mandatory(&b, "/A:", must(cvss31.Get("A")))

	// Temporal
	notMandatory(&b, "/E:", must(cvss31.Get("E")))
	notMandatory(&b, "/RL:", must(cvss31.Get("RL")))
	notMandatory(&b, "/RC:", must(cvss31.Get("RC")))

	// Environmental
	notMandatory(&b, "/CR:", must(cvss31.Get("CR")))
	notMandatory(&b, "/IR:", must(cvss31.Get("IR")))
	notMandatory(&b, "/AR:", must(cvss31.Get("AR")))
	notMandatory(&b, "/MAV:", must(cvss31.Get("MAV")))
	notMandatory(&b, "/MAC:", must(cvss31.Get("MAC")))
	notMandatory(&b, "/MPR:", must(cvss31.Get("MPR")))
	notMandatory(&b, "/MUI:", must(cvss31.Get("MUI")))
	notMandatory(&b, "/MS:", must(cvss31.Get("MS")))
	notMandatory(&b, "/MC:", must(cvss31.Get("MC")))
	notMandatory(&b, "/MI:", must(cvss31.Get("MI")))
	notMandatory(&b, "/MA:", must(cvss31.Get("MA")))

	return *(*string)(unsafe.Pointer(&b))
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func lenVec(cvss31 *CVSS31) int {
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
	if cvss31.exploitCodeMaturity != e_x {
		l += 4
	}
	if cvss31.remediationLevel != rl_x {
		l += 5
	}
	if cvss31.reportConfidence != rc_x {
		l += 5
	}

	// Environmental
	// - CR, IR, AR, MS, MC, MI, MA: 4
	// - MAV, MAC, MPR, MUI: 5
	// - each one adds a separator
	if cvss31.confidentialityRequirement != ciar_x {
		l += 5
	}
	if cvss31.integrityRequirement != ciar_x {
		l += 5
	}
	if cvss31.availabilityRequirement != ciar_x {
		l += 5
	}
	if cvss31.modifiedScope != ms_x {
		l += 5
	}
	if cvss31.modifiedConfidentiality != mcia_x {
		l += 5
	}
	if cvss31.modifiedIntegrity != mcia_x {
		l += 5
	}
	if cvss31.modifiedAvailability != mcia_x {
		l += 5
	}
	if cvss31.modifiedAttackVector != mav_x {
		l += 6
	}
	if cvss31.modifiedAttackComplexity != mac_x {
		l += 6
	}
	if cvss31.modifiedPrivilegesRequired != mpr_x {
		l += 6
	}
	if cvss31.modifiedUserInteraction != mui_x {
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

// CVSS31 embeds all the metric values defined by the CVSS v3.1
// specification.
// Attributes values must not be manipulated directly. Use Get
// and Set methods.
type CVSS31 struct {
	base
	temporal
	environmental
}

// base is the group of metrics defined with such name by the
// first.org CVSS v3.1 specification.
type base struct {
	// AV -> [N,A,L,P]. Mandatory
	attackVector uint8
	// AC -> [L,H]. Mandatory
	attackComplexity uint8
	// PR -> [N,L,H]. Mandatory
	privilegesRequired uint8
	// UI -> [N,R]. Mandatory
	userInteraction uint8
	// S -> [U,C]. Mandatory
	scope uint8
	// C -> [H,L,N]. Mandatory
	confidentiality uint8
	// I -> [H,L,N]. Mandatory
	integrity uint8
	// A -> [H,L,N]. Mandatory
	availability uint8
}

// temporal is the group of metrics defined with such name by the
// first.org CVSS v3.1 specification.
type temporal struct {
	// E -> [X,H,F,P,U]. Not mandatory
	exploitCodeMaturity uint8
	// RL -> [X,U,W,T,O]. Not mandatory
	remediationLevel uint8
	// RC -> [X,C,R,U]. Not mandatory
	reportConfidence uint8
}

// environmental is the group of metrics defined with such name by the
// first.org CVSS v3.1 specification.
type environmental struct {
	// CR -> [X,H,M,L]. Not mandatory
	confidentialityRequirement uint8
	// IR -> [X,H,M,L]. Not mandatory
	integrityRequirement uint8
	// AR -> [X,H,M,L]. Not mandatory
	availabilityRequirement uint8
	// MAV -> [X,N,A,L,P]. Not mandatory
	modifiedAttackVector uint8
	// MAC -> [X,L,H]. Not mandatory
	modifiedAttackComplexity uint8
	// MPR -> [X,N,L,H]. Not mandatory
	modifiedPrivilegesRequired uint8
	// MUI -> [X,N,R]. Not mandatory
	modifiedUserInteraction uint8
	// MS -> [X,U,C]. Not mandatory
	modifiedScope uint8
	// MC -> [X,N,L,H]. Not mandatory
	modifiedConfidentiality uint8
	// MI -> [X,N,L,H]. Not mandatory
	modifiedIntegrity uint8
	// MA -> [X,N,L,H]. Not mandatory
	modifiedAvailability uint8
}

// Get returns the value of the given metric abbreviation.
func (cvss31 CVSS31) Get(abv string) (r string, err error) {
	switch abv {
	// Base
	case "AV":
		switch cvss31.attackVector {
		case av_n:
			r = "N"
		case av_a:
			r = "A"
		case av_l:
			r = "L"
		case av_p:
			r = "P"
		}
	case "AC":
		switch cvss31.attackComplexity {
		case ac_l:
			r = "L"
		case ac_h:
			r = "H"
		}
	case "PR":
		switch cvss31.privilegesRequired {
		case pr_n:
			r = "N"
		case pr_l:
			r = "L"
		case pr_h:
			r = "H"
		}
	case "UI":
		switch cvss31.userInteraction {
		case ui_n:
			r = "N"
		case ui_r:
			r = "R"
		}
	case "S":
		switch cvss31.scope {
		case s_u:
			r = "U"
		case s_c:
			r = "C"
		}
	case "C":
		switch cvss31.confidentiality {
		case cia_h:
			r = "H"
		case cia_l:
			r = "L"
		case cia_n:
			r = "N"
		}
	case "I":
		switch cvss31.integrity {
		case cia_h:
			r = "H"
		case cia_l:
			r = "L"
		case cia_n:
			r = "N"
		}
	case "A":
		switch cvss31.availability {
		case cia_h:
			r = "H"
		case cia_l:
			r = "L"
		case cia_n:
			r = "N"
		}

	// Temporal
	case "E":
		switch cvss31.exploitCodeMaturity {
		case e_x:
			r = "X"
		case e_h:
			r = "H"
		case e_f:
			r = "F"
		case e_p:
			r = "P"
		case e_u:
			r = "U"
		}
	case "RL":
		switch cvss31.remediationLevel {
		case rl_x:
			r = "X"
		case rl_u:
			r = "U"
		case rl_w:
			r = "W"
		case rl_t:
			r = "T"
		case rl_o:
			r = "O"
		}
	case "RC":
		switch cvss31.reportConfidence {
		case rc_x:
			r = "X"
		case rc_c:
			r = "C"
		case rc_r:
			r = "R"
		case rc_u:
			r = "U"
		}

	// Environmental
	case "CR":
		switch cvss31.confidentialityRequirement {
		case ciar_x:
			r = "X"
		case ciar_h:
			r = "H"
		case ciar_m:
			r = "M"
		case ciar_l:
			r = "L"
		}
	case "IR":
		switch cvss31.integrityRequirement {
		case ciar_x:
			r = "X"
		case ciar_h:
			r = "H"
		case ciar_m:
			r = "M"
		case ciar_l:
			r = "L"
		}
	case "AR":
		switch cvss31.availabilityRequirement {
		case ciar_x:
			r = "X"
		case ciar_h:
			r = "H"
		case ciar_m:
			r = "M"
		case ciar_l:
			r = "L"
		}
	case "MAV":
		switch cvss31.modifiedAttackVector {
		case mav_x:
			r = "X"
		case mav_n:
			r = "N"
		case mav_a:
			r = "A"
		case mav_l:
			r = "L"
		case mav_p:
			r = "P"
		}
	case "MAC":
		switch cvss31.modifiedAttackComplexity {
		case mac_x:
			r = "X"
		case mac_l:
			r = "L"
		case mac_h:
			r = "H"
		}
	case "MPR":
		switch cvss31.modifiedPrivilegesRequired {
		case mpr_x:
			r = "X"
		case mpr_n:
			r = "N"
		case mpr_l:
			r = "L"
		case mpr_h:
			r = "H"
		}
	case "MUI":
		switch cvss31.modifiedUserInteraction {
		case mui_x:
			r = "X"
		case mui_n:
			r = "N"
		case mui_r:
			r = "R"
		}
	case "MS":
		switch cvss31.modifiedScope {
		case ms_x:
			r = "X"
		case ms_u:
			r = "U"
		case ms_c:
			r = "C"
		}
	case "MC":
		switch cvss31.modifiedConfidentiality {
		case mcia_x:
			r = "X"
		case mcia_n:
			r = "N"
		case mcia_l:
			r = "L"
		case mcia_h:
			r = "H"
		}
	case "MI":
		switch cvss31.modifiedIntegrity {
		case mcia_x:
			r = "X"
		case mcia_n:
			r = "N"
		case mcia_l:
			r = "L"
		case mcia_h:
			r = "H"
		}
	case "MA":
		switch cvss31.modifiedAvailability {
		case mcia_x:
			r = "X"
		case mcia_n:
			r = "N"
		case mcia_l:
			r = "L"
		case mcia_h:
			r = "H"
		}
	default:
		err = &ErrInvalidMetric{Abv: abv}
	}
	return
}

// Set sets the value of the given metric abbreviation.
func (cvss31 *CVSS31) Set(abv string, value string) error {
	switch abv {
	// Base
	case "AV":
		v, err := validate(value, []string{"N", "A", "L", "P"}, []uint8{av_n, av_a, av_l, av_p})
		if err != nil {
			return err
		}
		cvss31.attackVector = v
	case "AC":
		v, err := validate(value, []string{"L", "H"}, []uint8{ac_l, ac_h})
		if err != nil {
			return err
		}
		cvss31.attackComplexity = v
	case "PR":
		v, err := validate(value, []string{"N", "L", "H"}, []uint8{pr_n, pr_l, pr_h})
		if err != nil {
			return err
		}
		cvss31.privilegesRequired = v
	case "UI":
		v, err := validate(value, []string{"N", "R"}, []uint8{ui_n, ui_r})
		if err != nil {
			return err
		}
		cvss31.userInteraction = v
	case "S":
		v, err := validate(value, []string{"U", "C"}, []uint8{s_u, s_c})
		if err != nil {
			return err
		}
		cvss31.scope = v
	case "C":
		v, err := validate(value, []string{"H", "L", "N"}, []uint8{cia_h, cia_l, cia_n})
		if err != nil {
			return err
		}
		cvss31.confidentiality = v
	case "I":
		v, err := validate(value, []string{"H", "L", "N"}, []uint8{cia_h, cia_l, cia_n})
		if err != nil {
			return err
		}
		cvss31.integrity = v
	case "A":
		v, err := validate(value, []string{"H", "L", "N"}, []uint8{cia_h, cia_l, cia_n})
		if err != nil {
			return err
		}
		cvss31.availability = v

	// Temporal
	case "E":
		v, err := validate(value, []string{"X", "H", "F", "P", "U"}, []uint8{e_x, e_h, e_f, e_p, e_u})
		if err != nil {
			return err
		}
		cvss31.exploitCodeMaturity = v
	case "RL":
		v, err := validate(value, []string{"X", "U", "W", "T", "O"}, []uint8{rl_x, rl_u, rl_w, rl_t, rl_o})
		if err != nil {
			return err
		}
		cvss31.remediationLevel = v
	case "RC":
		v, err := validate(value, []string{"X", "C", "R", "U"}, []uint8{rc_x, rc_c, rc_r, rc_u})
		if err != nil {
			return err
		}
		cvss31.reportConfidence = v

	// Environmental
	case "CR":
		v, err := validate(value, []string{"X", "H", "M", "L"}, []uint8{ciar_x, ciar_h, ciar_m, ciar_l})
		if err != nil {
			return err
		}
		cvss31.confidentialityRequirement = v
	case "IR":
		v, err := validate(value, []string{"X", "H", "M", "L"}, []uint8{ciar_x, ciar_h, ciar_m, ciar_l})
		if err != nil {
			return err
		}
		cvss31.integrityRequirement = v
	case "AR":
		v, err := validate(value, []string{"X", "H", "M", "L"}, []uint8{ciar_x, ciar_h, ciar_m, ciar_l})
		if err != nil {
			return err
		}
		cvss31.availabilityRequirement = v
	case "MAV":
		v, err := validate(value, []string{"X", "N", "A", "L", "P"}, []uint8{mav_x, mav_n, mav_a, mav_l, mav_p})
		if err != nil {
			return err
		}
		cvss31.modifiedAttackVector = v
	case "MAC":
		v, err := validate(value, []string{"X", "L", "H"}, []uint8{mac_x, mac_l, mac_h})
		if err != nil {
			return err
		}
		cvss31.modifiedAttackComplexity = v
	case "MPR":
		v, err := validate(value, []string{"X", "N", "L", "H"}, []uint8{mpr_x, mpr_n, mpr_l, mpr_h})
		if err != nil {
			return err
		}
		cvss31.modifiedPrivilegesRequired = v
	case "MUI":
		v, err := validate(value, []string{"X", "N", "R"}, []uint8{mui_x, mui_n, mui_r})
		if err != nil {
			return err
		}
		cvss31.modifiedUserInteraction = v
	case "MS":
		v, err := validate(value, []string{"X", "U", "C"}, []uint8{ms_x, ms_u, ms_c})
		if err != nil {
			return err
		}
		cvss31.modifiedScope = v
	case "MC":
		v, err := validate(value, []string{"X", "N", "L", "H"}, []uint8{mcia_x, mcia_n, mcia_l, mcia_h})
		if err != nil {
			return err
		}
		cvss31.modifiedConfidentiality = v
	case "MI":
		v, err := validate(value, []string{"X", "N", "L", "H"}, []uint8{mcia_x, mcia_n, mcia_l, mcia_h})
		if err != nil {
			return err
		}
		cvss31.modifiedIntegrity = v
	case "MA":
		v, err := validate(value, []string{"X", "N", "L", "H"}, []uint8{mcia_x, mcia_n, mcia_l, mcia_h})
		if err != nil {
			return err
		}
		cvss31.modifiedAvailability = v
	default:
		return &ErrInvalidMetric{Abv: abv}
	}
	return nil
}

func validate(value string, enabled []string, values []uint8) (uint8, error) {
	// Check is valid
	for i, enbl := range enabled {
		if value == enbl {
			return values[i], nil
		}
	}
	return 0, ErrInvalidMetricValue
}

// BaseScore returns the CVSS v3.1's base score.
func (cvss31 CVSS31) BaseScore() float64 {
	impact := cvss31.Impact()
	exploitability := cvss31.Exploitability()
	if impact <= 0 {
		return 0
	}
	if cvss31.scope == s_u {
		return roundup(math.Min(impact+exploitability, 10))
	}
	return roundup(math.Min(1.08*(impact+exploitability), 10))
}

func (cvss31 CVSS31) Impact() float64 {
	iss := 1 - ((1 - cia(cvss31.confidentiality)) * (1 - cia(cvss31.integrity)) * (1 - cia(cvss31.availability)))
	if cvss31.scope == s_u {
		return 6.42 * iss
	}
	return 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
}

func (cvss31 CVSS31) Exploitability() float64 {
	return 8.22 * attackVector(cvss31.attackVector) * attackComplexity(cvss31.attackComplexity) * privilegesRequired(cvss31.privilegesRequired, cvss31.scope) * userInteraction(cvss31.userInteraction)
}

// TemporalScore returns the CVSS v3.1's temporal score.
func (cvss31 CVSS31) TemporalScore() float64 {
	return roundup(cvss31.BaseScore() * exploitCodeMaturity(cvss31.exploitCodeMaturity) * remediationLevel(cvss31.remediationLevel) * reportConfidence(cvss31.reportConfidence))
}

// EnvironmentalScore returns the CVSS v3.1's environmental score.
func (cvss31 CVSS31) EnvironmentalScore() float64 {
	// Choose which to use (use base if modified is not defined).
	// It is based on first.org online calculator's source code,
	// while it is not explicit in the specification which value
	// to use.
	mav := mod(cvss31.attackVector, cvss31.modifiedAttackVector, mav_x)
	mac := mod(cvss31.attackComplexity, cvss31.modifiedAttackComplexity, mac_x)
	mpr := mod(cvss31.privilegesRequired, cvss31.modifiedPrivilegesRequired, mpr_x)
	mui := mod(cvss31.userInteraction, cvss31.modifiedUserInteraction, mui_x)
	ms := mod(cvss31.scope, cvss31.modifiedScope, ms_x)
	mc := mod(cvss31.confidentiality, cvss31.modifiedConfidentiality, mcia_x)
	mi := mod(cvss31.integrity, cvss31.modifiedIntegrity, mcia_x)
	ma := mod(cvss31.availability, cvss31.modifiedAvailability, mcia_x)

	miss := math.Min(1-(1-ciar(cvss31.confidentialityRequirement)*cia(mc))*(1-ciar(cvss31.integrityRequirement)*cia(mi))*(1-ciar(cvss31.availabilityRequirement)*cia(ma)), 0.915)
	var modifiedImpact float64
	if ms == ms_u {
		modifiedImpact = 6.42 * miss
	} else {
		modifiedImpact = 7.52*(miss-0.029) - 3.25*math.Pow(miss*0.9731-0.02, 13)
	}
	modifiedExploitability := 8.22 * attackVector(mav) * attackComplexity(mac) * privilegesRequired(mpr, ms) * userInteraction(mui)
	if modifiedImpact <= 0 {
		return 0
	}
	if ms == ms_u {
		return roundup(roundup(math.Min(modifiedImpact+modifiedExploitability, 10)) * exploitCodeMaturity(cvss31.exploitCodeMaturity) * remediationLevel(cvss31.remediationLevel) * reportConfidence(cvss31.reportConfidence))
	}
	r := math.Min(1.08*(modifiedImpact+modifiedExploitability), 10)
	return roundup(roundup(r) * exploitCodeMaturity(cvss31.exploitCodeMaturity) * remediationLevel(cvss31.remediationLevel) * reportConfidence(cvss31.reportConfidence))
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

func attackVector(v uint8) float64 {
	switch v {
	case av_n:
		return 0.85
	case av_a:
		return 0.62
	case av_l:
		return 0.55
	case av_p:
		return 0.2
	default:
		panic(ErrInvalidMetricValue)
	}
}

func attackComplexity(v uint8) float64 {
	switch v {
	case ac_l:
		return 0.77
	case ac_h:
		return 0.44
	default:
		panic(ErrInvalidMetricValue)
	}
}

func privilegesRequired(v, scope uint8) float64 {
	switch v {
	case pr_n:
		return 0.85
	case pr_l:
		if scope == s_c {
			return 0.68
		}
		return 0.62
	case pr_h:
		if scope == s_c {
			return 0.5
		}
		return 0.27
	default:
		panic(ErrInvalidMetricValue)
	}
}

func userInteraction(v uint8) float64 {
	switch v {
	case ui_n:
		return 0.85
	case ui_r:
		return 0.62
	default:
		panic(ErrInvalidMetricValue)
	}
}

func cia(v uint8) float64 {
	switch v {
	case cia_h:
		return 0.56
	case cia_l:
		return 0.22
	case cia_n:
		return 0
	default:
		panic(ErrInvalidMetricValue)
	}
}

func exploitCodeMaturity(v uint8) float64 {
	switch v {
	case e_x:
		return 1
	case e_h:
		return 1
	case e_f:
		return 0.97
	case e_p:
		return 0.94
	case e_u:
		return 0.91
	default:
		panic(ErrInvalidMetricValue)
	}
}

func remediationLevel(v uint8) float64 {
	switch v {
	case rl_x:
		return 1
	case rl_u:
		return 1
	case rl_w:
		return 0.97
	case rl_t:
		return 0.96
	case rl_o:
		return 0.95
	default:
		panic(ErrInvalidMetricValue)
	}
}

func reportConfidence(v uint8) float64 {
	switch v {
	case rc_x:
		return 1
	case rc_c:
		return 1
	case rc_r:
		return 0.96
	case rc_u:
		return 0.92
	default:
		panic(ErrInvalidMetricValue)
	}
}

func ciar(v uint8) float64 {
	switch v {
	case ciar_x:
		return 1
	case ciar_h:
		return 1.5
	case ciar_m:
		return 1
	case ciar_l:
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

func mod(base, modified, x uint8) uint8 {
	if modified != x {
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
