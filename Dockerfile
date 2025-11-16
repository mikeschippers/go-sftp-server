FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod tidy  && go mod download && go mod verify

COPY . ./
RUN go build -o go-sftp-server

FROM alpine:latest
RUN apk add --no-cache ca-certificates

RUN adduser -D -u 10001 sftpuser
RUN mkdir -p /keys /data && chmod 0755 /keys /data
RUN chown -R sftpuser:sftpuser /keys /data

WORKDIR /data
COPY --from=builder /build/go-sftp-server /usr/local/bin/go-sftp-server

USER 10001

EXPOSE 2022
CMD ["/usr/local/bin/go-sftp-server"]
