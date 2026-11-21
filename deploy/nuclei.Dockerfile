# Scanner image for task containers. Templates are baked in at build time
# because a task container has no route to download them.
# Pin NUCLEI_IMAGE to a digest for repeatable builds.
ARG NUCLEI_IMAGE=projectdiscovery/nuclei:latest
FROM ${NUCLEI_IMAGE}
RUN nuclei -update-template-dir /opt/nuclei-templates -update-templates \
    && chmod -R a+rX /opt/nuclei-templates
COPY nuclei-canary.yaml /opt/vajra/canary.yaml
ENTRYPOINT ["nuclei"]
