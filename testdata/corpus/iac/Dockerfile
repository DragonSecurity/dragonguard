# Deliberately bad. Each line here is a trivy misconfiguration check that must
# keep firing.
FROM alpine:3.24@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35

# DS002: runs as root
USER root

# DS026: no HEALTHCHECK
# DS013: apk without --no-cache pins nothing and leaves the index behind
RUN apk add curl

# DS017: apk upgrade makes the image unreproducible
RUN apk upgrade

COPY . /app
CMD ["/app/server"]
