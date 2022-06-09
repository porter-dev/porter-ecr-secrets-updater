BINARY_NAME=secrets-updater

all: build

build:
	@go build -o ${BINARY_NAME} main.go

run:
	@go build -o ${BINARY_NAME} main.go
	@./${BINARY_NAME}

clean:
	@go clean
	@rm ${BINARY_NAME}
