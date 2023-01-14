package gocvss31

// The following values are used to reduce drastically the memory
// impact of a *CVSS31 which used string before as primar type.

// Base

const (
	av_ndef uint8 = iota
	av_n
	av_a
	av_l
	av_p
)

const (
	ac_ndef uint8 = iota
	ac_l
	ac_h
)

const (
	pr_ndef uint8 = iota
	pr_n
	pr_l
	pr_h
)

const (
	ui_ndef uint8 = iota
	ui_n
	ui_r
)

const (
	s_ndef uint8 = iota
	s_u
	s_c
)

const (
	cia_ndef uint8 = iota
	cia_h
	cia_l
	cia_n
)

// Temporal

const (
	e_x uint8 = iota
	e_h
	e_f
	e_p
	e_u
)

const (
	rl_x uint8 = iota
	rl_u
	rl_w
	rl_t
	rl_o
)

const (
	rc_x uint8 = iota
	rc_c
	rc_r
	rc_u
)

// Environmental

const (
	ciar_x uint8 = iota
	ciar_h
	ciar_m
	ciar_l
)

const (
	mav_x uint8 = iota
	mav_n
	mav_a
	mav_l
	mav_p
)

const (
	mac_x uint8 = iota
	mac_l
	mac_h
)

const (
	mpr_x uint8 = iota
	mpr_n
	mpr_l
	mpr_h
)

const (
	mui_x uint8 = iota
	mui_n
	mui_r
)

const (
	ms_x uint8 = iota
	ms_u
	ms_c
)

const (
	mcia_x uint8 = iota
	mcia_h
	mcia_l
	mcia_n
)
