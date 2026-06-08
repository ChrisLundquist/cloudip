# Multi-stage build: compile a static binary, ship it on a minimal base.
FROM golang:1.26 AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Static, stripped binary so it runs on a distroless/scratch base.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cloudattr ./cmd/cloudattr

# Distroless: no shell, small attack surface; ca-certificates for HTTPS fetches.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cloudattr /usr/local/bin/cloudattr

# Default: serve the database at /data/cloud.mmdb. Override the command to build,
# e.g. `docker run --rm -v $PWD/data:/data cloudip build --out /data/cloud.mmdb`.
WORKDIR /data
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/cloudattr"]
CMD ["serve", "--in", "/data/cloud.mmdb", "--http", ":8080", "--grpc", ":9090"]
