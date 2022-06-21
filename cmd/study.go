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
}
