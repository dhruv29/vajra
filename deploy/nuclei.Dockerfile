# Scanner image for task containers. Templates are baked in at build time
# because a task container has no route to download them.
# The base image is pinned by digest (nuclei v3.11.1 when this was written).
# The templates are fetched at build time and are not pinned: rebuild this
# image when you want newer checks, and keep the image you tested with for
# repeatable runs.
ARG NUCLEI_IMAGE=projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb
FROM ${NUCLEI_IMAGE}
RUN nuclei -update-template-dir /opt/nuclei-templates -update-templates \
    && chmod -R a+rX /opt/nuclei-templates
COPY nuclei-canary.yaml /opt/vajra/canary.yaml
ENTRYPOINT ["nuclei"]
