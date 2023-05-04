BENCH_FLAGS ?= -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem

MODULE_DIRS ?= ./20 ./30 ./31 ./benchmarks 

.PHONY: test
test:
	@$(foreach dir,$(MODULE_DIRS),(cd $(dir) && go test -race -v ./...) &&) true

.PHONY: cover
cover:
	go test -race -coverprofile=cover.out -coverpkg=./... ./...
	go tool cover -html=cover.out -o cover.html

.PHONY: bench
BENCH ?= .
bench:
	@$(foreach dir,$(MODULE_DIRS), ( \
		cd $(dir) && \
		go list ./... | xargs -n1 go test -bench=$(BENCH) -run="^$$" $(BENCH_FLAGS) \
	) &&) true
