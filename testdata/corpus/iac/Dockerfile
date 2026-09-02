# Deliberately bad. Each line here is a trivy misconfiguration check that must
# keep firing.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# DS002: runs as root
USER root

# DS026: no HEALTHCHECK
# DS013: apk without --no-cache pins nothing and leaves the index behind
RUN apk add curl

# DS017: apk upgrade makes the image unreproducible
RUN apk upgrade

COPY . /app
CMD ["/app/server"]
