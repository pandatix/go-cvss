# Go-CVSS

[![reference](https://godoc.org/github.com/pandatix/go-cvss/v5?status.svg=)](https://pkg.go.dev/github.com/pandatix/go-cvss)
[![go report](https://goreportcard.com/badge/github.com/pandatix/go-cvss)](https://goreportcard.com/report/github.com/pandatix/go-cvss)
[![codecov](https://codecov.io/gh/pandatix/go-cvss/branch/master/graph/badge.svg)](https://codecov.io/gh/pandatix/go-cvss)
[![CI](https://github.com/pandatix/go-cvss/actions/workflows/ci.yaml/badge.svg)](https://github.com/pandatix/go-cvss/actions?query=workflow%3Aci+)

Go module to manipulate Common Vulnerability Scoring System (CVSS).

Specified by [first.org](https://www.first.org/cvss/), the CVSS provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity.

It currently supports :
 - [X] [CVSS 2.0](https://www.first.org/cvss/v2/guide)
 - [X] [CVSS 3.0](https://www.first.org/cvss/v3.0/specification-document)
 - [X] [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
 - [ ] CVSS 4.0 (currently not published)

It won't support CVSS v1.0, as despite it was a good CVSS start, it can't get vectorized, abreviations and enumerations are not strongly specified, so the cohesion and interoperability can't be satisfied.

# How to use

The following code gives an example on how to use the present Go module.

It parses a CVSS v3.1 vector, then compute its base score and gives the associated rating.
It ends by printing it as the score followed by its rating, as it is often displayed.

```go
package main

import (
	"fmt"
	"log"

	gocvss31 "github.com/pandatix/go-cvss/31"
)

func main() {
	cvss31, err := gocvss31.ParseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
	if err != nil {
		log.Fatal(err)
	}
	baseScore := cvss31.BaseScore()
	rat, err := gocvss31.Rating(baseScore)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%.1f %s\n", baseScore, rat)
	// Prints "5.4 MEDIUM"
}
```

## Feedbacks

### CVSS v2.0

 - Section 3.3.1's base vector gives a base score of 7.8, while verbosely documented as 6.4.
 - `round_to_1_decimal` may have been specified, so that it's not guessed and adjusted to fit precomputed scores. It's not even CVSS v3.1 `roundup` specification.

### CVSS v3.0

 - Formulas are pretty, but complex to read as the variables does not refer to the specified abbreviations.
 - There is a lack of examples, as it's achieved by the CVSS v2.0 specification.

### CVSS v3.1

 - There is a lack of examples, as it's achieved by the CVSS v2.0 specification.
