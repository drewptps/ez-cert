FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ez-cert ./cmd/ez-cert

# ---

FROM alpine:3.21

RUN apk add --no-cache su-exec && \
    addgroup -S ezcert && adduser -S -G ezcert ezcert

WORKDIR /app

COPY --from=builder /build/ez-cert .
COPY web/ web/
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh && \
    mkdir -p data && chown -R ezcert:ezcert /app

EXPOSE 8080

ENV EZCERT_DATA_DIR=/app/data

ENTRYPOINT ["./entrypoint.sh"]
