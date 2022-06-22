# Go-CVSS

[![reference](https://godoc.org/github.com/pandatix/go-cvss/v5?status.svg=)](https://pkg.go.dev/github.com/pandatix/go-cvss)
[![go report](https://goreportcard.com/badge/github.com/pandatix/go-cvss)](https://goreportcard.com/report/github.com/pandatix/go-cvss)
[![codecov](https://codecov.io/gh/pandatix/go-cvss/branch/master/graph/badge.svg)](https://codecov.io/gh/pandatix/go-cvss)
[![CI](https://github.com/pandatix/go-cvss/actions/workflows/ci.yaml/badge.svg)](https://github.com/pandatix/go-cvss/actions?query=workflow%3Aci+)

Go module to manipulate Common Vulnerability Scoring System (CVSS).

Specified by [first.org](https://www.first.org/cvss/), the CVSS provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity.

It currently supports :
 - [ ] [CVSS 1.0](https://www.first.org/cvss/v1/guide)
 - [ ] [CVSS 2.0](https://www.first.org/cvss/v2/guide)
 - [ ] [CVSS 3.0](https://www.first.org/cvss/v3.0/specification-document)
 - [X] [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
 - [ ] CVSS 4.0 (currently not published)

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
