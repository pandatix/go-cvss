package gocvss40

import (
	"strings"
	"unsafe"
)

// This file is based on https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf.

const (
	header = "CVSS:4.0/"
)

// ParseVector parses a given vector string, validates it
// and returns a CVSS31.
func ParseVector(vector string) (*CVSS40, error) {
	// Check header
	if !strings.HasPrefix(vector, header) {
		return nil, ErrInvalidCVSSHeader
	}
	vector = vector[len(header):]

	// Allocate CVSS v4.0 object
	cvss40 := &CVSS40{
		u0: 0,
		u1: 0,
		u2: 0,
		u3: 0,
		u4: 0,
		u5: 0,
		u6: 0,
		u7: 0,
		u8: 0, // last 6 bits are not used
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
			if err := cvss40.Set(a, v); err != nil {

				return nil, err
			}
			start = i + 1
		}
	}

	// Check all base metrics are defined
	if !kvm.av {
		return nil, &ErrMissing{Abv: "AV"}
	}
	if !kvm.ac {
		return nil, &ErrMissing{Abv: "AC"}
	}
	if !kvm.at {
		return nil, &ErrMissing{Abv: "AT"}
	}
	if !kvm.pr {
		return nil, &ErrMissing{Abv: "PR"}
	}
	if !kvm.ui {
		return nil, &ErrMissing{Abv: "UI"}
	}
	if !kvm.vc {
		return nil, &ErrMissing{Abv: "VC"}
	}
	if !kvm.sc {
		return nil, &ErrMissing{Abv: "SC"}
	}
	if !kvm.vi {
		return nil, &ErrMissing{Abv: "VI"}
	}
	if !kvm.si {
		return nil, &ErrMissing{Abv: "SI"}
	}
	if !kvm.va {
		return nil, &ErrMissing{Abv: "VA"}
	}
	if !kvm.sa {
		return nil, &ErrMissing{Abv: "SA"}
	}

	return cvss40, nil
}

// splitCouple is more efficient than `strings.Cut` as it is
// specialised on the ':' char.
func splitCouple(couple string) (string, string) {
	for i := 0; i < len(couple); i++ {
		if couple[i] == ':' {
			return couple[:i], couple[i+1:]
		}
	}
	return couple, ""
}

// Vector returns the CVSS v4.0 vector string representation.
func (cvss40 CVSS40) Vector() string {
	l := lenVec(&cvss40)
	b := make([]byte, 0, l)
	b = append(b, header...)

	// Base
	mandatory(&b, "AV:", cvss40.get("AV"))
	mandatory(&b, "/AC:", cvss40.get("AC"))
	mandatory(&b, "/AT:", cvss40.get("AT"))
	mandatory(&b, "/PR:", cvss40.get("PR"))
	mandatory(&b, "/UI:", cvss40.get("UI"))
	mandatory(&b, "/VC:", cvss40.get("VC"))
	mandatory(&b, "/SC:", cvss40.get("SC"))
	mandatory(&b, "/VI:", cvss40.get("VI"))
	mandatory(&b, "/SI:", cvss40.get("SI"))
	mandatory(&b, "/VA:", cvss40.get("VA"))
	mandatory(&b, "/SA:", cvss40.get("SA"))

	// Threat
	notMandatory(&b, "/E:", cvss40.get("E"))

	// Environmental
	notMandatory(&b, "/CR:", cvss40.get("CR"))
	notMandatory(&b, "/IR:", cvss40.get("IR"))
	notMandatory(&b, "/AR:", cvss40.get("AR"))
	notMandatory(&b, "/MAV:", cvss40.get("MAV"))
	notMandatory(&b, "/MAC:", cvss40.get("MAC"))
	notMandatory(&b, "/MAT:", cvss40.get("MAT"))
	notMandatory(&b, "/MPR:", cvss40.get("MPR"))
	notMandatory(&b, "/MUI:", cvss40.get("MUI"))
	notMandatory(&b, "/MVC:", cvss40.get("MVC"))
	notMandatory(&b, "/MVI:", cvss40.get("MVI"))
	notMandatory(&b, "/MVA:", cvss40.get("MVA"))
	notMandatory(&b, "/MSC:", cvss40.get("MSC"))
	notMandatory(&b, "/MSI:", cvss40.get("MSI"))
	notMandatory(&b, "/MSA:", cvss40.get("MSA"))

	// Supplemental
	notMandatory(&b, "/S:", cvss40.get("S"))
	notMandatory(&b, "/AU:", cvss40.get("AU"))
	notMandatory(&b, "/R:", cvss40.get("R"))
	notMandatory(&b, "/V:", cvss40.get("V"))
	notMandatory(&b, "/RE:", cvss40.get("RE"))
	notMandatory(&b, "/U:", cvss40.get("U"))

	return unsafe.String(&b[0], l)
}

func lenVec(cvss40 *CVSS40) int {
	// Header: constant, so fixed (9)
	// Base:
	// - AV, AC, AT, PR, UI, VC, SC, VI, SI, VA, SA: 4
	// - separators: 10
	// Total: 11*4 + 10 = 54
	l := len(header) + 54

	// Threat:
	// - E: 3
	// - each one adds a separator
	// shortcut for "E" metric
	if (cvss40.u2 & 0b00001100) != 0 {
		l += 4
	}

	// Environmental:
	// - CR, IR, AR: 4
	// - MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA: 5
	// - each one adds a separator
	// shortcut for "CR" metric
	if (cvss40.u2 & 0b00000011) != 0 {
		l += 5
	}
	// shortcut for "IR" metric
	if (cvss40.u3 & 0b11000000) != 0 {
		l += 5
	}
	// shortcut for "AR" metric
	if (cvss40.u3 & 0b00110000) != 0 {
		l += 5
	}
	// shortcut for "MAV" metric
	if (cvss40.u3 & 0b00001110) != 0 {
		l += 6
	}
	// shortcut for "MAC" metric
	if (cvss40.u3&0b00000001) != 0 || (cvss40.u4&0b10000000) != 0 {
		l += 6
	}
	// shortcut for "MAT" metric
	if (cvss40.u4 & 0b01100000) != 0 {
		l += 6
	}
	// shortcut for "MPR" metric
	if (cvss40.u4 & 0b00011000) != 0 {
		l += 6
	}
	// shortcut for "MUI" metric
	if (cvss40.u4 & 0b00000110) != 0 {
		l += 6
	}
	// shortcut for "MVC" metric
	if (cvss40.u4&0b00000001) != 0 || (cvss40.u5&0b10000000) != 0 {
		l += 6
	}
	// shortcut for "MVI" metric
	if (cvss40.u5 & 0b01100000) != 0 {
		l += 6
	}
	// shortcut for "MVA" metric
	if (cvss40.u5 & 0b00011000) != 0 {
		l += 6
	}
	// shortcut for "MSC" metric
	if (cvss40.u5 & 0b00000110) != 0 {
		l += 6
	}
	// shortcut for "MSI" metric
	if (cvss40.u5&0b00000001) != 0 || (cvss40.u6&0b11000000) != 0 {
		l += 6
	}
	// shortcut for "MSA" metric
	if (cvss40.u6 & 0b00111000) != 0 {
		l += 6
	}

	// Supplemental:
	// - S, R, V: 3
	// - AU, RE: 4
	// - U depends on value
	// - each one adds a separator
	// shortcut for "S" metric
	if (cvss40.u6 & 0b00000110) != 0 {
		l += 4
	}
	// shortcut for "AU" metric
	if (cvss40.u6&0b00000001) != 0 || (cvss40.u7&0b10000000) != 0 {
		l += 5
	}
	// shortcut for "R" metric
	if (cvss40.u7 & 0b01100000) != 0 {
		l += 4
	}
	// shortcut for "V" metric
	if (cvss40.u7 & 0b00011000) != 0 {
		l += 4
	}
	// shortcut for "RE" metric
	if (cvss40.u7 & 0b00000110) != 0 {
		l += 5
	}
	// "U" metric
	u := ((cvss40.u7 & 0b00000001) << 2) | ((cvss40.u8 & 0b11000000) >> 6)
	switch u {
	case u_clear, u_green, u_amber:
		l += 8
	case u_red:
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

// CVSS40 embeds all the metric values defined by the CVSS v4
// specification.
type CVSS40 struct {
	u0, u1, u2, u3, u4, u5, u6, u7, u8 uint8
}

// Get returns the value of the given metric abbreviation.
func (cvss40 CVSS40) Get(abv string) (r string, err error) {
	switch abv {
	// Base
	case "AV":
		v := (cvss40.u0 & 0b11000000) >> 6
		switch v {
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
		v := (cvss40.u0 & 0b00100000) >> 5
		switch v {
		case ac_h:
			r = "H"
		case ac_l:
			r = "L"
		}
	case "AT":
		v := (cvss40.u0 & 0b00010000) >> 4
		switch v {
		case at_n:
			r = "N"
		case at_p:
			r = "P"
		}
	case "PR":
		v := (cvss40.u0 & 0b00001100) >> 2
		switch v {
		case pr_h:
			r = "H"
		case pr_l:
			r = "L"
		case pr_n:
			r = "N"
		}
	case "UI":
		v := cvss40.u0 & 0b00000011
		switch v {
		case ui_n:
			r = "N"
		case ui_p:
			r = "P"
		case ui_a:
			r = "A"
		}
	case "VC":
		v := (cvss40.u1 & 0b11000000) >> 6
		switch v {
		case vscia_h:
			r = "H"
		case vscia_l:
			r = "L"
		case vscia_n:
			r = "N"
		}
	case "SC":
		v := (cvss40.u1 & 0b00110000) >> 4
		switch v {
		case vscia_h:
			r = "H"
		case vscia_l:
			r = "L"
		case vscia_n:
			r = "N"
		}
	case "VI":
		v := (cvss40.u1 & 0b00001100) >> 2
		switch v {
		case vscia_h:
			r = "H"
		case vscia_l:
			r = "L"
		case vscia_n:
			r = "N"
		}
	case "SI":
		v := cvss40.u1 & 0b00000011
		switch v {
		case vscia_h:
			r = "H"
		case vscia_l:
			r = "L"
		case vscia_n:
			r = "N"
		}
	case "VA":
		v := (cvss40.u2 & 0b11000000) >> 6
		switch v {
		case vscia_h:
			r = "H"
		case vscia_l:
			r = "L"
		case vscia_n:
			r = "N"
		}
	case "SA":
		v := (cvss40.u2 & 0b00110000) >> 4
		switch v {
		case vscia_h:
			r = "H"
		case vscia_l:
			r = "L"
		case vscia_n:
			r = "N"
		}

	// Threat
	case "E":
		v := (cvss40.u2 & 0b00001100) >> 2
		switch v {
		case e_x:
			r = "X"
		case e_a:
			r = "A"
		case e_p:
			r = "P"
		case e_u:
			r = "U"
		}

	// Environmental
	case "CR":
		v := cvss40.u2 & 0b00000011
		switch v {
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
		v := (cvss40.u3 & 0b11000000) >> 6
		switch v {
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
		v := (cvss40.u3 & 0b00110000) >> 4
		switch v {
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
		v := (cvss40.u3 & 0b00001110) >> 1
		switch v {
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
		v := ((cvss40.u3 & 0b00000001) << 1) | ((cvss40.u4 & 0b10000000) >> 7)
		switch v {
		case mac_x:
			r = "X"
		case mac_h:
			r = "H"
		case mac_l:
			r = "L"
		}
	case "MAT":
		v := (cvss40.u4 & 0b01100000) >> 5
		switch v {
		case mat_x:
			r = "X"
		case mat_n:
			r = "N"
		case mat_p:
			r = "P"
		}
	case "MPR":
		v := (cvss40.u4 & 0b00011000) >> 3
		switch v {
		case mpr_x:
			r = "X"
		case mpr_h:
			r = "H"
		case mpr_l:
			r = "L"
		case mpr_n:
			r = "N"
		}
	case "MUI":
		v := (cvss40.u4 & 0b00000110) >> 1
		switch v {
		case mui_x:
			r = "X"
		case mui_n:
			r = "N"
		case mui_p:
			r = "P"
		case mui_a:
			r = "A"
		}
	case "MVC":
		v := ((cvss40.u4 & 0b00000001) << 1) | ((cvss40.u5 & 0b10000000) >> 7)
		switch v {
		case mvcia_x:
			r = "X"
		case mvcia_h:
			r = "H"
		case mvcia_l:
			r = "L"
		case mvcia_n:
			r = "N"
		}
	case "MVI":
		v := (cvss40.u5 & 0b01100000) >> 5
		switch v {
		case mvcia_x:
			r = "X"
		case mvcia_h:
			r = "H"
		case mvcia_l:
			r = "L"
		case mvcia_n:
			r = "N"
		}
	case "MVA":
		v := (cvss40.u5 & 0b00011000) >> 3
		switch v {
		case mvcia_x:
			r = "X"
		case mvcia_h:
			r = "H"
		case mvcia_l:
			r = "L"
		case mvcia_n:
			r = "N"
		}
	case "MSC":
		v := (cvss40.u5 & 0b00000110) >> 1
		switch v {
		case msc_x:
			r = "X"
		case msc_h:
			r = "H"
		case msc_l:
			r = "L"
		case msc_n:
			r = "N"
		}
	case "MSI":
		v := ((cvss40.u5 & 0b00000001) << 2) | ((cvss40.u6 & 0b11000000) >> 6)
		switch v {
		case msia_x:
			r = "X"
		case msia_h:
			r = "H"
		case msia_l:
			r = "L"
		case msia_n:
			r = "N"
		case msia_s:
			r = "S"
		}
	case "MSA":
		v := (cvss40.u6 & 0b00111000) >> 3
		switch v {
		case msia_x:
			r = "X"
		case msia_h:
			r = "H"
		case msia_l:
			r = "L"
		case msia_n:
			r = "N"
		case msia_s:
			r = "S"
		}

	// Supplemental
	case "S":
		v := (cvss40.u6 & 0b00000110) >> 1
		switch v {
		case s_x:
			r = "X"
		case s_n:
			r = "N"
		case s_p:
			r = "P"
		}
	case "AU":
		v := ((cvss40.u6 & 0b00000001) << 1) | ((cvss40.u7 & 0b10000000) >> 7)
		switch v {
		case au_x:
			r = "X"
		case au_n:
			r = "N"
		case au_y:
			r = "Y"
		}
	case "R":
		v := (cvss40.u7 & 0b01100000) >> 5
		switch v {
		case r_x:
			r = "X"
		case r_a:
			r = "A"
		case r_u:
			r = "U"
		case r_i:
			r = "I"
		}
	case "V":
		v := (cvss40.u7 & 0b00011000) >> 3
		switch v {
		case v_x:
			r = "X"
		case v_d:
			r = "D"
		case v_c:
			r = "C"
		}
	case "RE":
		v := (cvss40.u7 & 0b00000110) >> 1
		switch v {
		case re_x:
			r = "X"
		case re_l:
			r = "L"
		case re_m:
			r = "M"
		case re_h:
			r = "H"
		}
	case "U":
		v := ((cvss40.u7 & 0b00000001) << 2) | ((cvss40.u8 & 0b11000000) >> 6)
		switch v {
		case u_x:
			r = "X"
		case u_clear:
			r = "Clear"
		case u_green:
			r = "Green"
		case u_amber:
			r = "Amber"
		case u_red:
			r = "Red"
		}
	default:
		err = &ErrInvalidMetric{Abv: abv}
	}
	return
}

// Set sets the value of the given metric abbreviation.
func (cvss40 *CVSS40) Set(abv, value string) error {
	switch abv {
	// Base
	case "AV":
		v, err := validate(value, []string{"N", "A", "L", "P"})
		if err != nil {
			return err
		}
		cvss40.u0 = (cvss40.u0 & 0b00111111) | (v << 6)
	case "AC":
		v, err := validate(value, []string{"H", "L"})
		if err != nil {
			return err
		}
		cvss40.u0 = (cvss40.u0 & 0b11011111) | (v << 5)
	case "AT":
		v, err := validate(value, []string{"N", "P"})
		if err != nil {
			return err
		}
		cvss40.u0 = (cvss40.u0 & 0b11101111) | (v << 4)
	case "PR":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u0 = (cvss40.u0 & 0b11110011) | (v << 2)
	case "UI":
		v, err := validate(value, []string{"N", "P", "A"})
		if err != nil {
			return err
		}
		cvss40.u0 = (cvss40.u0 & 0b11111100) | v
	case "VC":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u1 = (cvss40.u1 & 0b00111111) | (v << 6)
	case "SC":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u1 = (cvss40.u1 & 0b11001111) | (v << 4)
	case "VI":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u1 = (cvss40.u1 & 0b11110011) | (v << 2)
	case "SI":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u1 = (cvss40.u1 & 0b11111100) | v
	case "VA":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u2 = (cvss40.u2 & 0b00111111) | (v << 6)
	case "SA":
		v, err := validate(value, []string{"H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u2 = (cvss40.u2 & 0b11001111) | (v << 4)

	// Threat
	case "E":
		v, err := validate(value, []string{"X", "A", "P", "U"})
		if err != nil {
			return err
		}
		cvss40.u2 = (cvss40.u2 & 0b11110011) | (v << 2)

	// Environmental
	case "CR":
		v, err := validate(value, []string{"X", "H", "M", "L"})
		if err != nil {
			return err
		}
		cvss40.u2 = (cvss40.u2 & 0b11111100) | v
	case "IR":
		v, err := validate(value, []string{"X", "H", "M", "L"})
		if err != nil {
			return err
		}
		cvss40.u3 = (cvss40.u3 & 0b00111111) | (v << 6)
	case "AR":
		v, err := validate(value, []string{"X", "H", "M", "L"})
		if err != nil {
			return err
		}
		cvss40.u3 = (cvss40.u3 & 0b11001111) | (v << 4)
	case "MAV":
		v, err := validate(value, []string{"X", "N", "A", "L", "P"})
		if err != nil {
			return err
		}
		cvss40.u3 = (cvss40.u3 & 0b11110001) | (v << 1)
	case "MAC":
		v, err := validate(value, []string{"X", "H", "L"})
		if err != nil {
			return err
		}
		cvss40.u3 = (cvss40.u3 & 0b11111110) | ((v & 10) >> 1)
		cvss40.u4 = (cvss40.u4 & 0b01111111) | ((v & 01) << 7)
	case "MAT":
		v, err := validate(value, []string{"X", "N", "P"})
		if err != nil {
			return err
		}
		cvss40.u4 = (cvss40.u4 & 0b10011111) | (v << 5)
	case "MPR":
		v, err := validate(value, []string{"X", "H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u4 = (cvss40.u4 & 0b11100111) | (v << 3)
	case "MUI":
		v, err := validate(value, []string{"X", "N", "P", "A"})
		if err != nil {
			return err
		}
		cvss40.u4 = (cvss40.u4 & 0b11111001) | (v << 1)
	case "MVC":
		v, err := validate(value, []string{"X", "H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u4 = (cvss40.u4 & 0b11111110) | ((v & 0b10) >> 1)
		cvss40.u5 = (cvss40.u5 & 0b01111111) | ((v & 0b01) << 7)
	case "MVI":
		v, err := validate(value, []string{"X", "H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u5 = (cvss40.u5 & 0b10011111) | (v << 5)
	case "MVA":
		v, err := validate(value, []string{"X", "H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u5 = (cvss40.u5 & 0b11100111) | (v << 3)
	case "MSC":
		v, err := validate(value, []string{"X", "H", "L", "N"})
		if err != nil {
			return err
		}
		cvss40.u5 = (cvss40.u5 & 0b11111001) | (v << 1)
	case "MSI":
		v, err := validate(value, []string{"X", "H", "L", "N", "S"})
		if err != nil {
			return err
		}
		cvss40.u5 = (cvss40.u5 & 0b11111110) | ((v & 0b100) >> 2)
		cvss40.u6 = (cvss40.u6 & 0b00111111) | ((v & 0b011) << 6)
	case "MSA":
		v, err := validate(value, []string{"X", "H", "L", "N", "S"})
		if err != nil {
			return err
		}
		cvss40.u6 = (cvss40.u6 & 0b11000111) | (v << 3)

	// Supplemental
	case "S":
		v, err := validate(value, []string{"X", "N", "P"})
		if err != nil {
			return err
		}
		cvss40.u6 = (cvss40.u6 & 0b11111001) | (v << 1)
	case "AU":
		v, err := validate(value, []string{"X", "N", "Y"})
		if err != nil {
			return err
		}
		cvss40.u6 = (cvss40.u6 & 0b11111110) | ((v & 0b10) >> 1)
		cvss40.u7 = (cvss40.u7 & 0b01111111) | ((v & 0b01) << 7)
	case "R":
		v, err := validate(value, []string{"X", "A", "U", "I"})
		if err != nil {
			return err
		}
		cvss40.u7 = (cvss40.u7 & 0b10011111) | (v << 5)
	case "V":
		v, err := validate(value, []string{"X", "D", "C"})
		if err != nil {
			return err
		}
		cvss40.u7 = (cvss40.u7 & 0b11100111) | (v << 3)
	case "RE":
		v, err := validate(value, []string{"X", "L", "M", "H"})
		if err != nil {
			return err
		}
		cvss40.u7 = (cvss40.u7 & 0b11111001) | (v << 1)
	case "U":
		v, err := validate(value, []string{"X", "Clear", "Green", "Amber", "Red"})
		if err != nil {
			return err
		}
		cvss40.u7 = (cvss40.u7 & 0b11111110) | ((v & 0b100) >> 2)
		// cvss40.u8 & 0b00000000 is not computed as it will always be 0
		// and the remaining 6 bytes are not used.
		cvss40.u8 = (v & 0b011) << 6
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

// get is used for internal purposes only.
func (cvss40 CVSS40) get(abv string) string {
	str, _ := cvss40.Get(abv)
	return str
}

// Score returns the CVSS v4.0's score.
// Use Nomenclature for getting groups used by computation.
func (cvss40 CVSS40) Score() float64 {
	// TODO implement score computation when specification is fixed
	return 0
}

// Nomenclature returns the CVSS v4.0 configuration used when scoring.
// Check CVSS v4.0 specification Section 1.3 for more info.
func (cvss40 CVSS40) Nomenclature() string {
	// Check if any metric of groups is defined
	t := (cvss40.u2 & 0b00001100) != 0
	e := (cvss40.u2&0b00000011) != 0 ||
		cvss40.u3 != 0 || cvss40.u4 != 0 || cvss40.u5 != 0 ||
		(cvss40.u6&0b11111000) != 0

	if t {
		if e {
			return "CVSS-BTE"
		}
		return "CVSS-BT"
	}
	if e {
		return "CVSS-BE"
	}
	return "CVSS-B"
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

// kvm stands for Key-Value Map, and is used to make sure each
// metric is defined only once, as documented by the CVSS v3.1
// specification document, section 6 "Vector String" paragraph 3.
// Using this avoids a map that escapes to heap for each call of
// ParseVector, as its size is known and wont evolve.
type kvm struct {
	// base metrics
	av, ac, at, pr, ui, vc, sc, vi, si, va, sa bool
	// threat metrics
	e bool
	// environmental metrics
	cr, ir, ar, mav, mac, mat, mpr, mui, mvc, mvi, mva, msc, msi, msa bool
	// supplemental metrics
	s, au, r, v, re, u bool
}

func (kvm *kvm) Set(abv string) error {
	var dst *bool
	switch abv {
	case "AV":
		dst = &kvm.av
	case "AC":
		dst = &kvm.ac
	case "AT":
		dst = &kvm.at
	case "PR":
		dst = &kvm.pr
	case "UI":
		dst = &kvm.ui
	case "VC":
		dst = &kvm.vc
	case "SC":
		dst = &kvm.sc
	case "VI":
		dst = &kvm.vi
	case "SI":
		dst = &kvm.si
	case "VA":
		dst = &kvm.va
	case "SA":
		dst = &kvm.sa
	case "E":
		dst = &kvm.e
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
	case "MAT":
		dst = &kvm.mat
	case "MPR":
		dst = &kvm.mpr
	case "MUI":
		dst = &kvm.mui
	case "MVC":
		dst = &kvm.mvc
	case "MVI":
		dst = &kvm.mvi
	case "MVA":
		dst = &kvm.mva
	case "MSC":
		dst = &kvm.msc
	case "MSI":
		dst = &kvm.msi
	case "MSA":
		dst = &kvm.msa
	case "S":
		dst = &kvm.s
	case "AU":
		dst = &kvm.au
	case "R":
		dst = &kvm.r
	case "V":
		dst = &kvm.v
	case "RE":
		dst = &kvm.re
	case "U":
		dst = &kvm.u
	default:
		return &ErrInvalidMetric{Abv: abv}
	}
	if *dst {
		return &ErrDefinedN{Abv: abv}
	}
	*dst = true
	return nil
}
