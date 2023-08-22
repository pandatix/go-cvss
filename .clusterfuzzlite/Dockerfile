FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/pandatix/go-cvss.git
RUN go install github.com/AdamKorcz/go-118-fuzz-build@latest
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/go-cvss
