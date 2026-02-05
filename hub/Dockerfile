FROM golang:1.23-alpine

WORKDIR /hub

COPY . .

RUN go mod init hub || true && \
    go mod tidy && \
    go build -o hub .

EXPOSE 8080

CMD ["./hub"]