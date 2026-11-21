# Analyser image for static scans. It runs with no network, so it only needs
# the semgrep binary; rules come from a host directory or a path baked in here.
# The base image is pinned by digest (semgrep 1.185.0 when this was written).
ARG SEMGREP_IMAGE=semgrep/semgrep@sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d
FROM ${SEMGREP_IMAGE}
ENTRYPOINT ["semgrep"]
