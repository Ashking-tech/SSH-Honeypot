FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o honeypot .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/honeypot .
RUN mkdir -p /app/keys
EXPOSE 2222
CMD ["./honeypot"]