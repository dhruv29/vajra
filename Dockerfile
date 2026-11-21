# The Vajra binary: used as the egress gate container, as the sandboxed HTTP
# probe, and as the CLI. Base images are pinned by digest so that a rebuild
# gives the same result; update the digests deliberately (see `make digests`).
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
# -trimpath and an empty build ID keep the binary free of local paths, so two
# builds of the same commit are byte-identical.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /vajra ./cmd/vajra

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /vajra /vajra
USER 65532:65532
ENTRYPOINT ["/vajra"]
