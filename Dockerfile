# The Vajra binary: used as the egress gate container and as the CLI.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /vajra ./cmd/vajra

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /vajra /vajra
USER 65532:65532
ENTRYPOINT ["/vajra"]
