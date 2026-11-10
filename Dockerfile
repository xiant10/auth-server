# syntax=docker/dockerfile:1

FROM golang:1.27.3-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/t10-modkit ./third_party/t10-modkit
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/ ./cmd/...

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=build /out/auth-server /out/authctl /usr/local/bin/
COPY --from=build /src/deploy/setup.sh /usr/local/bin/auth-setup
# The reviewed client list ships with the code that reads it.
COPY --from=build /src/clients.yaml /etc/t10-auth/clients.yaml

ENV AUTH_CLIENTS_FILE=/etc/t10-auth/clients.yaml

USER 65534:65534

EXPOSE 18000

ENTRYPOINT ["/usr/local/bin/auth-server"]
