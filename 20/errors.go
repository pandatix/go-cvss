package gocvss20

import (
	"errors"
	"fmt"
)

var (
	ErrTooShortVector     = errors.New("too short vector")
	ErrInvalidMetricOrder = errors.New("invalid metric order")
	ErrInvalidMetricValue = errors.New("invalid metric value")
)

// ErrDefinedN is an error return by ParseVector when the
// given vector has metrics abbreviations defined multiple times.
type ErrDefinedN struct {
	Abv string
}

func (err ErrDefinedN) Error() string {
	return fmt.Sprintf("given CVSS v3.1 vector has %s metric abbreviation defined after vector end", err.Abv)
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
