package gocvss30

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidCVSSHeader  = errors.New("invalid CVSS v3.0 header")
	ErrTooShortVector     = errors.New("too short vector")
	ErrInvalidMetricValue = errors.New("invalid metric value")
	ErrInvalidCVSSVersion = errors.New("invalid CVSS version")
	ErrOutOfBoundsScore   = errors.New("out of bounds score")
)

// ErrBaseScore is an error returned by ParseVector when the
// given vector have missing base score attributes.
type ErrBaseScore struct {
	Missings []string
}

func (err ErrBaseScore) Error() string {
	return fmt.Sprintf("base score is missing metrics %v", err.Missings)
}

var _ error = (*ErrBaseScore)(nil)

// ErrDefinedN is an error return by ParseVector when the
// given vector has metrics abbreviations defined multiple times.
type ErrDefinedN struct {
	Abv []string
}

func (err ErrDefinedN) Error() string {
	return fmt.Sprintf("given CVSS v3.0 vector has %v metric abbreviations defined multiple times", err.Abv)
}

var _ error = (*ErrDefinedN)(nil)

// ErrInvalidMetric is an error returned when a given
// metric does not exist.
type ErrInvalidMetric struct {
	Abv string
}

func (err ErrInvalidMetric) Error() string {
	return fmt.Sprintf("invalid metric abbreviation : %s", err.Abv)
}

var _ error = (*ErrInvalidMetric)(nil)
