FROM golang:1.24-alpine AS build
WORKDIR /src
COPY internal.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/forgeops-internal internal.go

FROM alpine:3.20
RUN adduser -D -H forgeops
COPY --from=build /out/forgeops-internal /usr/local/bin/forgeops-internal
USER forgeops
EXPOSE 9100
CMD ["forgeops-internal"]
