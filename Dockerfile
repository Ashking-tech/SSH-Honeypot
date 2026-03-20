FROM golang:1.25-alpine AS builder
WORKDIR /app
ENV GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o honeypot .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/honeypot .
RUN mkdir -p /app/keys
EXPOSE 2222
CMD ["./honeypot"]