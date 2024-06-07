FROM golang:1.21-alpine3.18 AS Builder

ENV CGO_ENABLED=1
ENV GOOS=linux
ENV TZ=America/Sao_Paulo
ENV SHELL=/bin/bash

WORKDIR /app
COPY . .

RUN apk add --no-cache sqlite=3.41.2-r3 \
   poppler-utils=23.05.0-r0 \
   build-base=0.5-r3 \
   bash=5.2.15-r5

RUN go mod tidy \
 && export BUILD_VERSION=`git rev-parse --short HEAD` \
 && export BUILD_DATE=`date +"%Y-%m-%d_%H:%M:%S"` \
 && export APP_NAME=`go list -m` \
 && go build -installsuffix "static" \
    -ldflags "-X $APP_NAME/src/shared/logger.COMMIT_HASH=$COMMIT_HASH -X $APP_NAME/src/shared/logger.BUILD_DATE=$BUILD_DATE -X $APP_NAME/src/shared/logger.APP_NAME=$APP_NAME -s -w" \
    -o /webapp ./cmd/webapp/main.go
