module github.com/pandatix/go-cvss/differential

go 1.19

replace github.com/pandatix/go-cvss => ../

require (
	github.com/attwad/gocvss v0.0.0-20150121011547-982b87a1eb8d
	github.com/bunji2/cvssv3 v0.0.0-20191208005905-79ce3fdeaf96
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/goark/go-cvss v1.6.4
	github.com/pandatix/go-cvss v0.5.1
	github.com/umisama/go-cvss v0.0.0-20150430082624-a4ad666ead9b
	github.com/zntrio/mitre v0.0.2-0.20230302090312-8e21160b0691
)

require (
	github.com/goark/errs v1.1.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)
