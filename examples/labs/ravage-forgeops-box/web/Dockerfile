FROM golang:1.24-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/forgeops main.go

FROM alpine:3.20
RUN adduser -D -H forgeops
COPY --from=build /out/forgeops /usr/local/bin/forgeops
USER forgeops
EXPOSE 8080
CMD ["forgeops"]
