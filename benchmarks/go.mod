module github.com/pandatix/go-cvss/benchmarks

go 1.19

replace github.com/pandatix/go-cvss => ../

require (
	github.com/bunji2/cvssv3 v0.0.0-20191208005905-79ce3fdeaf96
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/goark/go-cvss v1.3.0
	github.com/pandatix/go-cvss v0.4.2
	github.com/slimsec/cvss v0.0.0-20150707152743-289f023e1db1
	github.com/umisama/go-cvss v0.0.0-20150430082624-a4ad666ead9b
)

require github.com/goark/errs v1.1.0 // indirect
