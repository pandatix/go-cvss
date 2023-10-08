package gocvss40

import (
	"log"
	"strings"
	"unsafe"
)

// This file is based on https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf.

const (
	header = "CVSS:4.0"
)

var (
	order = [][]string{
		// Base
		{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"},
		// Threat
		{"E"},
		// Environmental
		{"CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"},
		// Supplemental
		{"S", "AU", "R", "V", "RE", "U"},
	}
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

	cut := 0
	slci, orderi := 0, 0
	for i := 1; i <= len(vector); i++ {
		if i != len(vector) && vector[i] != '/' {
			continue
		}

		// Remove leading /
		pt := vector[cut:min(i, len(vector))]
		cut = i
		if !strings.HasPrefix(pt, "/") {
			return nil, ErrInvalidMetricValue
		}
		pt = pt[1:]
		// Cut on colon
		abv, v, _ := strings.Cut(pt, ":")
		// Check (non)mandatory values
		for {
			if (slci == 0 && abv != order[0][orderi]) || slci == len(order) {
				return nil, ErrInvalidMetricOrder
			}
			out := abv == order[slci][orderi]
			orderi++
			if orderi == len(order[slci]) {
				slci++
				orderi = 0
			}
			if out {
				break
			}
		}

		if err := cvss40.Set(abv, v); err != nil {
			return nil, err
		}
	}
	// Check whole last metric group is specified in vector (=> i == 0)
	if slci == 0 {
		return nil, ErrTooShortVector
	}

	return cvss40, nil
}

// Vector returns the CVSS v4.0 vector string representation.
func (cvss40 CVSS40) Vector() string {
	l := lenVec(&cvss40)
	b := make([]byte, 0, l)
	b = append(b, header...)

	// Base
	mandatory(&b, "/AV:", cvss40.get("AV"))
	mandatory(&b, "/AC:", cvss40.get("AC"))
	mandatory(&b, "/AT:", cvss40.get("AT"))
	mandatory(&b, "/PR:", cvss40.get("PR"))
	mandatory(&b, "/UI:", cvss40.get("UI"))
	mandatory(&b, "/VC:", cvss40.get("VC"))
	mandatory(&b, "/VI:", cvss40.get("VI"))
	mandatory(&b, "/VA:", cvss40.get("VA"))
	mandatory(&b, "/SC:", cvss40.get("SC"))
	mandatory(&b, "/SI:", cvss40.get("SI"))
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
	// Header: constant, so fixed (11)
	// Base:
	// - AV, AC, AT, PR, UI, VC, SC, VI, SI, VA, SA: 4
	// - separators: 11
	// Total: 11*4 + 11 = 55
	l := len(header) + 55

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

// get is used for internal purposes only.
func (cvss40 CVSS40) get(abv string) string {
	str, _ := cvss40.Get(abv)
	return str
}

// Score returns the CVSS v4.0's score.
// Use Nomenclature for getting groups used by computation.
func (cvss40 CVSS40) Score() float64 {
	// Get metrics
	// TODO fetch environmental instead when defined
	// av := mod((cvss40.u0&0b11000000)>>6, (cvss40.u3&0b00001110)>>1)
	// ac := mod((cvss40.u0&0b00100000)>>5, ((cvss40.u3&0b00000001)<<1)|((cvss40.u4&0b10000000)>>7))
	// at := mod((cvss40.u0&0b00010000)>>4, (cvss40.u4&0b01100000)>>5)
	// pr := mod((cvss40.u0&0b00001100)>>2, (cvss40.u4&0b00011000)>>3)
	// ui := mod(cvss40.u0&0b00000011, (cvss40.u4&0b00000110)>>1)
	// vc := mod((cvss40.u1&0b11000000)>>6, ((cvss40.u4&0b00000001)<<1)|((cvss40.u5&0b10000000)>>7))
	// sc := mod((cvss40.u1&0b00110000)>>4, (cvss40.u5&0b00000110)>>1)
	// vi := mod((cvss40.u1&0b00001100)>>2, (cvss40.u5&0b01100000)>>5)
	// si := mod(cvss40.u1&0b00000011, ((cvss40.u5&0b00000001)<<2)|((cvss40.u6&0b11000000)>>6))
	// va := mod((cvss40.u2&0b11000000)>>6, (cvss40.u5&0b00011000)>>3)
	// sa := mod((cvss40.u2&0b00110000)>>4, (cvss40.u6&0b00111000)>>3)
	av := (cvss40.u0 & 0b11000000) >> 6
	ac := (cvss40.u0 & 0b00100000) >> 5
	at := (cvss40.u0 & 0b00010000) >> 4
	pr := (cvss40.u0 & 0b00001100) >> 2
	ui := cvss40.u0 & 0b00000011
	vc := (cvss40.u1 & 0b11000000) >> 6
	sc := (cvss40.u1 & 0b00110000) >> 4
	vi := (cvss40.u1 & 0b00001100) >> 2
	si := cvss40.u1 & 0b00000011
	va := (cvss40.u2 & 0b11000000) >> 6
	sa := (cvss40.u2 & 0b00110000) >> 4

	// Compute EQs
	// => EQ1 - Table 25
	eq1 := 0
	if av == av_n && pr == pr_n && ui == ui_n {
		eq1 = 0
	} else if (av == av_n || pr == pr_n || ui == ui_n) && !(av == av_n && pr == pr_n && ui == ui_n) && !(av == av_p) {
		eq1 = 1
	} else if av == av_p || !(av == av_n || pr == pr_n || ui == ui_n) {
		eq1 = 2
	} else {
		log.Fatalf("invalid CVSS configuration: AV:%s/PR:%s/UI:%s\n", cvss40.get("AV"), cvss40.get("PR"), cvss40.get("UI"))
	}
	// => EQ2 - Table 26
	eq2 := 0
	if ac == ac_l && at == at_n {
		eq2 = 0
	} else if !(ac == ac_l && at == at_n) {
		eq2 = 1
	} else {
		log.Fatalf("invalid CVSS configuration: AC:%s/AT:%s\n", cvss40.get("AC"), cvss40.get("AT"))
	}
	// => EQ3 - Table 27
	eq3 := 0
	if vc == vscia_h && vi == vscia_h {
		eq3 = 0
	} else if !(vc == vscia_h && vi == vscia_h) && (vc == vscia_h || vi == vscia_h || va == vscia_h) {
		eq3 = 1
	} else if !(vc == vscia_h || vi == vscia_h || va == vscia_h) {
		eq3 = 2
	} else {
		log.Fatalf("invalid CVSS configuration: VC:%s/VI:%s/VA:%s\n", cvss40.get("VC"), cvss40.get("VI"), cvss40.get("VA"))
	}
	// => EQ4 - Table 28
	eq4 := 0
	if cvss40.get("MSI") == "S" || cvss40.get("MSA") == "S" {
		eq4 = 0
	} else if !(cvss40.get("MSI") == "S" && cvss40.get("MSA") == "S") && (sc == vscia_h || si == vscia_h || sa == vscia_h) {
		eq4 = 1
	} else if !(cvss40.get("MSI") == "S" && cvss40.get("MSA") == "S") && !(sc == vscia_h || si == vscia_h || sa == vscia_h) {
		eq4 = 2
	} else {
		log.Fatalf("invalid CVSS configuration: MSI:%s/MSA:%s/SC:%s/SI:%s/SA:%s\n", cvss40.get("MSI"), cvss40.get("MSA"), cvss40.get("SC"), cvss40.get("SI"), cvss40.get("SA"))
	}
	// => EQ5 - Table 29
	eq5 := 0
	if cvss40.get("E") == "A" {
		eq5 = 0
	} else if cvss40.get("E") == "P" {
		eq5 = 1
	} else if cvss40.get("E") == "U" {
		eq5 = 2
	} else {
		log.Fatalf("invalid CVSS configuration: E:%s\n", cvss40.get("E"))
	}
	// => EQ6 - Table 30
	eq6 := 0
	if av == av_n && pr == pr_n && ui == ui_n {
		eq6 = 0
	} else if (cvss40.get("CR") == "H" && cvss40.get("VC") == "H") || (cvss40.get("IR") == "H" && vi == vscia_h) || (cvss40.get("AR") == "H" && va == vscia_h) {
		eq6 = 1
	} else {
		log.Fatalf("invalid CVSS configuration: AV:%s/PR:%s/UI:%s/CR:%s/VC:%s/IR:%s/VI:%s/AR:%s/VA:%s\n", cvss40.get("AV"), cvss40.get("PR"), cvss40.get("UI"), cvss40.get("CR"), cvss40.get("VC"), cvss40.get("IR"), cvss40.get("VI"), cvss40.get("AR"), cvss40.get("VA"))
	}
	// => EQ3+EQ6 - Table 31
	eq3eq6 := 0
	if vc == vscia_h && vi == vscia_h && (cvss40.get("CR") == "H" || cvss40.get("IR") == "H" || (cvss40.get("AR") == "H" && va == vscia_h)) {
		eq3eq6 = 00
	} else if vc == vscia_h && vi == vscia_h && !(cvss40.get("CR") == "H" || cvss40.get("IR") == "H") && !(cvss40.get("AR") == "H" && va == vscia_h) {
		eq3eq6 = 01
	} else if !(vc == vscia_h && vi == vscia_h) && (vc == vscia_h || vi == vscia_h || va == vscia_h) && (cvss40.get("CR") == "H" && cvss40.get("VC") == "H") || (cvss40.get("IR") == "H" && vi == vscia_h) || (cvss40.get("AR") == "H" && va == vscia_h) {
		eq3eq6 = 10
	} else if !(vc == vscia_h && vi == vscia_h) && (vc == vscia_h || vi == vscia_h || va == vscia_h) && !(cvss40.get("CR") == "H" && cvss40.get("VC") == "H") && !(cvss40.get("IR") == "H" && vi == vscia_h) && !(cvss40.get("AR") == "H" && va == vscia_h) {
		eq3eq6 = 11
	} else if !(vc == vscia_h || vi == vscia_h || va == vscia_h) && (cvss40.get("CR") == "H" && cvss40.get("VC") == "H") || (cvss40.get("IR") == "H" && vi == vscia_h) || (cvss40.get("AR") == "H" && va == vscia_h) {
		eq3eq6 = 20
	} else if !(vc == vscia_h || vi == vscia_h || va == vscia_h) && !(cvss40.get("CR") == "H" && cvss40.get("VC") == "H") && !(cvss40.get("IR") == "H" && vi == vscia_h) && !(cvss40.get("AR") == "H" && va == vscia_h) {
		eq3eq6 = 21
	} else {
		log.Fatalf("invalid CVSS configuration: CR:%s/VC:%s/IR:%s/VI:%s/AR:%s/VA:%s\n", cvss40.get("CR"), cvss40.get("VC"), cvss40.get("IR"), cvss40.get("VI"), cvss40.get("AR"), cvss40.get("VA"))
	}

	return float64(eq1) + float64(eq2) + float64(eq3) + float64(eq4) + float64(eq5) + float64(eq6) + float64(eq3eq6)
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
