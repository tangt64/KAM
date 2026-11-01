FROM docker.io/library/golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" -o /kam .
FROM scratch
COPY --from=build /kam /kam
USER 65532:65532
ENTRYPOINT ["/kam"]
