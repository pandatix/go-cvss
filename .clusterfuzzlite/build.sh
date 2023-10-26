#!/bin/bash

go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/pandatix/go-cvss/20 FuzzParseVector fuzz_parse_vector_20
compile_native_go_fuzzer github.com/pandatix/go-cvss/30 FuzzParseVector fuzz_parse_vector_30
compile_native_go_fuzzer github.com/pandatix/go-cvss/31 FuzzParseVector fuzz_parse_vector_31
compile_native_go_fuzzer github.com/pandatix/go-cvss/40 FuzzParseVector fuzz_parse_vector_40
