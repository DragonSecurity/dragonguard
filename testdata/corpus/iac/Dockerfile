# Deliberately bad. Each line here is a trivy misconfiguration check that must
# keep firing.
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

# DS002: runs as root
USER root

# DS026: no HEALTHCHECK
# DS013: apk without --no-cache pins nothing and leaves the index behind
RUN apk add curl

# DS017: apk upgrade makes the image unreproducible
RUN apk upgrade

COPY . /app
CMD ["/app/server"]
