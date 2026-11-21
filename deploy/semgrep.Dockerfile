# Analyser image for static scans. It runs with no network, so it only needs
# the semgrep binary; rules come from a host directory or a path baked in here.
# Pin SEMGREP_IMAGE to a digest for repeatable builds.
ARG SEMGREP_IMAGE=semgrep/semgrep:latest
FROM ${SEMGREP_IMAGE}
ENTRYPOINT ["semgrep"]
