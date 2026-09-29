# Build stage: Go toolchain to compile and test the whole project.
# The official golang image is published for both linux/amd64 and linux/arm64,
# so this builds natively on x86 and on Apple Silicon.
FROM golang:1.23-alpine AS build

WORKDIR /src

# Resolve dependencies first so the module cache layer survives source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY common/ ./common/
COPY server/ ./server/
COPY client/ ./client/

RUN go test ./...

# Version info compiled into the binary. The build context has neither common.sh
# nor the git metadata (see .dockerignore), so both values are passed in by
# docker/build.sh and default to 'unknown' for a plain 'docker build'.
ARG APP_VERSION=unknown
ARG GIT_REF=unknown

# CGO_ENABLED=0 produces a static binary (the project is pure Go), which lets the
# final stage be a bare base image. GOOS/GOARCH are deliberately left at their
# defaults so the binary is built for the architecture Docker is building for.
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-X rpm-signing/common.AppVersion=${APP_VERSION} -X rpm-signing/common.GitRef=${GIT_REF}" \
    -o /out/server ./server

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-X rpm-signing/common.AppVersion=${APP_VERSION} -X rpm-signing/common.GitRef=${GIT_REF}" \
    -o /out/client ./client

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
    -ldflags "-X rpm-signing/common.AppVersion=${APP_VERSION} -X rpm-signing/common.GitRef=${GIT_REF}" \
    -o /out/client_arm64 ./client

# Final stage: the two binaries only, no toolchain or sources.
FROM alpine:3.21

COPY --from=build /out/server /usr/local/bin/server
# The client is shipped so the server can hand it out via GET /clientDownload;
# point 'rpm_sign_client_binary' at this path in the mounted configuration file.
COPY --from=build /out/client /usr/local/bin/client
COPY --from=build /out/client_arm64 /usr/local/bin/client_arm64

# Default listen address of the server; informational only.
EXPOSE 8080

# The configuration file is expected to be mounted at /config/rpm-signing.properties, e.g.
#   docker run -v ./rpm-signing.properties:/config/rpm-signing.properties:ro -p 8080:8080 <image>
ENTRYPOINT ["/usr/local/bin/server", "-c", "/config/rpm-signing.properties"]
