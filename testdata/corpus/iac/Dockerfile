# Deliberately bad. Each line here is a trivy misconfiguration check that must
# keep firing.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# DS002: runs as root
USER root

# DS026: no HEALTHCHECK
# DS013: apk without --no-cache pins nothing and leaves the index behind
RUN apk add curl

# DS017: apk upgrade makes the image unreproducible
RUN apk upgrade

COPY . /app
CMD ["/app/server"]
