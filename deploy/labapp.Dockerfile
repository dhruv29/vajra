# The INTENTIONALLY VULNERABLE lab application that scripts/e2e.sh scores
# Vajra against (bench/labapp). For the isolated test lab only. Build it from
# the repository root:
#   docker build -t vajra-labapp:local -f deploy/labapp.Dockerfile .
# Base images are pinned by the same digests as the main Dockerfile.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod ./
COPY bench/labapp ./bench/labapp
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /labapp ./bench/labapp

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /labapp /labapp
USER 65532:65532
ENTRYPOINT ["/labapp"]
CMD ["-listen", ":80"]
