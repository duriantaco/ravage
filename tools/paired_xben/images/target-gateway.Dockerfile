# syntax=docker/dockerfile:1.18.0@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

# linux/amd64 manifest for Docker Official Image
# python:3.12.11-slim-bookworm. Do not replace this with a mutable tag.
FROM docker.io/library/python@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49

ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/duriantaco/ravage" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="Ravage paired-XBEN target request meter"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/ravage

WORKDIR /opt/ravage
COPY --chmod=0444 packages/ravage/src/ravage/xben_parts/http_meter_gateway.py \
    ravage/xben_parts/http_meter_gateway.py

# The evaluator overrides the entrypoint explicitly and runs as uid/gid 65532
# with a read-only root filesystem and a private tmpfs receipt directory.
ENTRYPOINT ["python3"]
