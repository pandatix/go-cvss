module github.com/pandatix/go-cvss/differential

go 1.22

replace github.com/pandatix/go-cvss => ../

replace github.com/quay/claircore/toolkit => github.com/hdonnay/claircore/toolkit v0.0.0-20240131190225-911cf68106a8

require (
	github.com/attwad/gocvss v0.0.0-20150121011547-982b87a1eb8d
	github.com/bunji2/cvssv3 v0.0.0-20191208005905-79ce3fdeaf96
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/goark/go-cvss v1.6.6
	github.com/pandatix/go-cvss v0.5.2
	github.com/quay/claircore/toolkit v1.1.2-0.20240124010924-3f84aa609a95
	github.com/umisama/go-cvss v0.0.0-20150430082624-a4ad666ead9b
	github.com/zntrio/mitre v1.0.1
)

require (
	github.com/goark/errs v1.2.2 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)
