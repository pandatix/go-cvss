# Go-CVSS

[![reference](https://godoc.org/github.com/pandatix/go-cvss/v5?status.svg=)](https://pkg.go.dev/github.com/pandatix/go-cvss)
[![go report](https://goreportcard.com/badge/github.com/pandatix/go-cvss)](https://goreportcard.com/report/github.com/pandatix/go-cvss)
[![Coverage Status](https://coveralls.io/repos/github/pandatix/go-cvss/badge.svg?branch=master)](https://coveralls.io/github/pandatix/go-cvss?branch=master)
[![CI](https://github.com/pandatix/go-cvss/actions/workflows/ci.yaml/badge.svg)](https://github.com/pandatix/go-cvss/actions?query=workflow%3Aci+)
[![CodeQL](https://github.com/pandatix/go-cvss/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/pandatix/go-cvss/actions/workflows/codeql-analysis.yml)

Go-CVSS is a blazing-fast, low allocations and small memory-usage Go module made to manipulate Common Vulnerability Scoring System (CVSS).

Specified by [first.org](https://www.first.org/cvss/), the CVSS provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity.

It currently supports :
 - [X] [CVSS 2.0](https://www.first.org/cvss/v2/guide)
 - [X] [CVSS 3.0](https://www.first.org/cvss/v3.0/specification-document)
 - [X] [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
 - [ ] CVSS 4.0 (currently not published)

It won't support CVSS v1.0, as despite it was a good CVSS start, it can't get vectorized, abbreviations and enumerations are not strongly specified, so the cohesion and interoperability can't be satisfied.

## Summary

 - [How to use](#how-to-use)
 - [A word on performances](#a-word-on-performances)
   - [CVSS v2.0](#cvss-v20)
   - [CVSS v3.0](#cvss-v30)
   - [CVSS v3.1](#cvss-v31)
   - [How it works](#how-it-works)
   - [Comparison](#comparison)
 - [Feedbacks](#feedbacks)
   - [CVSS v2.0](#cvss-v20-1)
   - [CVSS v3.0](#cvss-v30-1)
   - [CVSS v3.1](#cvss-v31-1)

## How to use

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

## A word on performances

We are aware that manipulating a CVSS object does not provide the most value to your business needs.
This is why we paid a big attention to the performances of this module.

What we made is making this module **0 to 1 allocs/op** for the whole API.
This reduces drastically the pressure on the Garbage Collector, without cutting through security (fuzzing ensures the API does not contain obvious security issues). It also reduces the time and bytes per operation to a really acceptable level.

The following shows the performances results.
We challenge any other Go implementation to do better :stuck_out_tongue_winking_eye:

### CVSS v2.0

```
goos: linux
goarch: amd64
pkg: github.com/pandatix/go-cvss/20
cpu: Intel(R) Core(TM) i7-8086K CPU @ 4.00GHz
BenchmarkParseVector_Base-12                 4531821           234.1 ns/op         4 B/op          1 allocs/op
BenchmarkParseVector_WithTempAndEnv-12       2166142           562.8 ns/op         4 B/op          1 allocs/op
BenchmarkCVSS20Vector-12                     3951876           280.4 ns/op        80 B/op          1 allocs/op
BenchmarkCVSS20Get-12                      136042681           8.352 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS20Set-12                       80306113           14.87 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS20BaseScore-12                 21735627           55.46 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS20TemporalScore-12             14529606           83.19 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS20EnvironmentalScore-12         7741926           138.3 ns/op         0 B/op          0 allocs/op
```

### CVSS v3.0

```
goos: linux
goarch: amd64
pkg: github.com/pandatix/go-cvss/30
cpu: Intel(R) Core(TM) i7-8086K CPU @ 4.00GHz
BenchmarkParseVector_Base-12                 3888972           275.2 ns/op         8 B/op          1 allocs/op
BenchmarkParseVector_WithTempAndEnv-12       1713600           629.9 ns/op         8 B/op          1 allocs/op
BenchmarkCVSS30Vector-12                     2233227           478.6 ns/op        96 B/op          1 allocs/op
BenchmarkCVSS30Get-12                       72043518           14.88 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS30Set-12                       65622488           17.64 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS30BaseScore-12                  8671944           136.8 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS30TemporalScore-12              6249768           190.0 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS30EnvironmentalScore-12         3404409           306.9 ns/op         0 B/op          0 allocs/op
```

### CVSS v3.1

```
goos: linux
goarch: amd64
pkg: github.com/pandatix/go-cvss/31
cpu: Intel(R) Core(TM) i7-8086K CPU @ 4.00GHz
BenchmarkParseVector_Base-12                 4211038           285.3 ns/op         8 B/op          1 allocs/op
BenchmarkParseVector_WithTempAndEnv-12       1732320           660.9 ns/op         8 B/op          1 allocs/op
BenchmarkCVSS31Vector-12                     2580373           477.8 ns/op        96 B/op          1 allocs/op
BenchmarkCVSS31Get-12                       96923160           13.85 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS31Set-12                       65558484           17.31 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS31BaseScore-12                  9199874           130.6 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS31TemporalScore-12              6063409           182.8 ns/op         0 B/op          0 allocs/op
BenchmarkCVSS31EnvironmentalScore-12         3897127           302.7 ns/op         0 B/op          0 allocs/op
```

### How it works

If you are looking at the internals, you'll see it's hard to read.
Indeed, this has been highly optimised, so the code is no longer easily readable.

Before continuing, the optimizations discussed later goes against the [Knuth's words](https://web.archive.org/web/20210425190711if_/https://pic.plover.com/knuth-GOTO.pdf), but the maintenance is **our** problem, and the impacts in your code base is major for the best.

There is four major parts in this optimizations:
 1. **on-the-fly parsing** when parsing v3 vectors, meaning no buffer have to be used when parsing one. This mainly reduces the allocs/op indicator for the function that did most allocations.
 2. **buffer reuse** and share when parsing v2 vectors, using a `sync.Pool` of a predetermined buffer size. This reduces the allocs/op indicator for the v2 parsing function for the second function that did most allocations.
 3. **allocate-once buffer**, so that the vectorizing function counts what memory it will need then allocates and fill it. This mainly reduces the allocs/op indicator for the vectorizing function. At this step, we are at 0-1 allocs/op, but still at 352 B/op for parsing and 92 B/op for vectorizing (for v3, but the same applies to v2).
 4. **information theory based optimizations**, with focus on each bit usage. This is detailed next. This finally reduces the B/op indicator, leading to an highily optimized module.

Fortunately, those optimizations always improved (or did not affect drastically) the ns/op indicator, so no balance had to be considered. The only balance was making our job hard so yours is better.

The idea behind the fourth otimization lies on the information theory: if you have an information that could be represented by a finite set of elements, meaning you can enumerate them, then you could store them using `n` bits such that `n=ceil(log2(s))` with `s` the size of this finite set.

In the case of CVSS, each attribute has its finite number of metrics with their finite set of possible values. It implies we fit in this case, so we could make it real. That's what we did.

In this module, we represent each metric set in the `values.go` file, so we enumerate them. Then, we count how many bits are necessary to store this, and use a slice of corresponding bytes (`bytes=ceil(bits/8)` with `bits` the sum of all `n`).
To determine those, we build for each version a table with those data, leading us to determine that, for instance with CVSS v3, we need `44` bits so `6` bytes.

Then, the only issue arises with implementing this idea. We define a scheme to specify what each bit is used for, and pull out hairs with bit masking and slice manip. Notice that it imply the vector object does not have attributes for corresponding metrics, but have some `uint8` attributes, making this hard to read (and reverse btw).

We are aware that this could still be improved as we could transitively state that CVSS vectors are a set of finite combinations, so we could enumerate them. This would lead us to a finite set of `573308928000` combinations for v3 and `139968000` for v2, which could be respectively represented on `40` bits (`=log2(573308928000)`) that makes `5` bytes and `28` bits (`=log2(139968000)`) that still makes `4`.
This imply that CVSS v2 implementation can't be improved by this process.
Nevertheless, this has been judged over-optimizations for now, but a motivated developer may do it for a cookie :laughing:

### Comparison

The following are the results of the comparison with others Go CVSS implementations, based on its own [benchmarking suite](./benchmarks).

For each metric (`% ns/op`, `% B/op`, `% allocs/op`), the result of an implementation is normalised to the result of the current module for this given metric.
This simply comparisons and shows how well it performs.

Benchmarks results for CVSS v2.
<div align="center">
	<img src="res/benchmarks-results-cvss-v2.png">
</div>

Benchmarks results for CVSS v3.
<div align="center">
	<img src="res/benchmarks-results-cvss-v3.png">
</div>

Based on those results, we can see that this implementation does not scores best for each metric, but the overall shows **it is better than others at parsing and vectorizing**. As those are the core of this Go module API, with support and compliance of both v2 and v3, we consider our Go module better to use.

The _poor_ results of `BaseScore` is due to the internal optimizations that takes more cycles to fetch the values, but the time efficiency is still gigantic (between 10 and 30 ns/op in our experiment).

## Feedbacks

### CVSS v2.0

 - Section 3.3.1's base vector gives a base score of 7.8, while verbosely documented as 6.4.
 - `round_to_1_decimal` may have been specified, so that it's not guessed and adjusted to fit precomputed scores. It's not even CVSS v3.1 `roundup` specification.

### CVSS v3.0

 - Formulas are pretty, but complex to read as the variables does not refer to the specified abbreviations.
 - There is a lack of examples, as it's achieved by the CVSS v2.0 specification.

### CVSS v3.1

 - There is a lack of examples, as it's achieved by the CVSS v2.0 specification.
