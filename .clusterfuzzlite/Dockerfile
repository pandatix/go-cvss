FROM gcr.io/oss-fuzz-base/base-builder-go@6381f9b0ecc8a6bb36ab16fc7a2a01d0c48df1fd4f510ca2babb98defe6213d8
RUN git clone --depth 1 https://github.com/pandatix/go-cvss.git
RUN go install github.com/AdamKorcz/go-118-fuzz-build@2b5cbb29f3e2e08ef2032ac4dc88a40a3a1e9e5f
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/go-cvss
