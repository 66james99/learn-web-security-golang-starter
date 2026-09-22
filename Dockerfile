FROM golang:1.27.0-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/bearly-secure ./cmd/server \
	&& CGO_ENABLED=0 go build -o /out/bearly-attacker-lab ./cmd/attackerlab

FROM alpine:3.22

WORKDIR /app
RUN apk add --no-cache ca-certificates \
	&& adduser -s -g bearly bearly -D \
	&& mkdir -p /app/data/uploads /app/data/fixtures \
	&& chown bearly:bearly ./data

COPY --from=build /out/bearly-secure ./bearly-secure
COPY --from=build /out/bearly-attacker-lab ./bearly-attacker-lab
COPY --from=build /src/attacker-lab ./attacker-lab
COPY --from=build /src/web ./web
COPY --from=build /src/data/fixtures ./data/fixtures

USER bearly
EXPOSE 3030 4040
CMD ["./bearly-secure"]
