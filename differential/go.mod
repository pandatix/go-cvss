module github.com/pandatix/go-cvss/differential

go 1.19

replace github.com/pandatix/go-cvss => ../

// TLS certificate is invalid, switching to github repository
replace go.zenithar.org/mitre => github.com/zntrio/mitre v0.0.1

require (
	github.com/attwad/gocvss v0.0.0-20150121011547-982b87a1eb8d
	github.com/bunji2/cvssv3 v0.0.0-20191208005905-79ce3fdeaf96
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/goark/go-cvss v1.6.0
	github.com/pandatix/go-cvss v0.5.1
	github.com/umisama/go-cvss v0.0.0-20150430082624-a4ad666ead9b
	go.zenithar.org/mitre v0.0.0-00010101000000-000000000000
)

require (
	github.com/goark/errs v1.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
)
