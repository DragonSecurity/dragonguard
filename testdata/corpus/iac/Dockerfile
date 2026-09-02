# Deliberately bad. Each line here is a trivy misconfiguration check that must
# keep firing.
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# DS002: runs as root
USER root

# DS026: no HEALTHCHECK
# DS013: apk without --no-cache pins nothing and leaves the index behind
RUN apk add curl

# DS017: apk upgrade makes the image unreproducible
RUN apk upgrade

COPY . /app
CMD ["/app/server"]
