.PHONY: build clean deploy 

build: 
	export GO111MODULE=on
	go mod tidy
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/authz authz/main.go
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/service1 service1/main.go
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/service2 service2/main.go

clean:
	rm -rf ./bin ./vendor **/go.sum

test:
	opa test -c -f=json ./authz -v

deploy: clean build test
	sls deploy --verbose

