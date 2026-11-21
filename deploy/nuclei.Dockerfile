# Scanner image for task containers. Templates are baked in at build time
# because a task container has no route to download them.
#
# Both halves are pinned: the scanner by image digest (nuclei v3.11.1 when
# this was written) and the templates by release and checksum, so two builds
# of this file contain the same checks. To get newer checks, raise the version
# and replace the checksum with the SHA-256 of the new release archive.
ARG NUCLEI_IMAGE=projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb
FROM ${NUCLEI_IMAGE}
ARG TEMPLATES_VERSION=10.5.2
ARG TEMPLATES_SHA256=016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574
ADD --checksum=sha256:${TEMPLATES_SHA256} \
    https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${TEMPLATES_VERSION}.tar.gz \
    /tmp/templates.tar.gz
# The last test makes an empty or partial template set fail the build here,
# instead of surfacing later as a scan that silently checks nothing.
RUN mkdir -p /opt/nuclei-templates \
    && tar -xzf /tmp/templates.tar.gz -C /opt/nuclei-templates --strip-components=1 \
    && chmod -R a+rX /opt/nuclei-templates \
    && test -s /opt/nuclei-templates/http/exposures/configs/git-config.yaml
COPY nuclei-canary.yaml /opt/vajra/canary.yaml
ENTRYPOINT ["nuclei"]
