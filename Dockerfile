FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ez-cert ./cmd/ez-cert

# ---

FROM alpine:3.21

RUN addgroup -S ezcert && adduser -S -G ezcert ezcert

WORKDIR /app

COPY --from=builder /build/ez-cert .
COPY web/ web/

RUN mkdir -p data && chown -R ezcert:ezcert /app

USER ezcert

EXPOSE 8080

ENV EZCERT_DATA_DIR=/app/data

ENTRYPOINT ["./ez-cert"]
