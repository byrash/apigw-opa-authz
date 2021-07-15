package main

import (
	"bytes"
	"context"
	_ "embed"

	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

//go:embed opa_apigw.rego
var module string

//go:embed opa_authz_data.json
var authzData string

var store storage.Store
var compiler *ast.Compiler
var ctx context.Context

func main() {
	log.Println("cold start")

	// just compile OPA policies once per container
	compileOpaPolicy()

	lambda.Start(Handler)
}

func track(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func compileOpaPolicy() {
	defer track(time.Now(), "compileOpaPolicy()")
	ctx = context.Background()
	// TODO: Data store. Should pull this from s3.
	store = inmem.NewFromReader(bytes.NewBufferString(authzData))
	parsed, err := ast.ParseModule("opa_apigw.rego", module)
	if err != nil {
		panic(err)
	}
	compiler = ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{
		"opa_apigw.rego": parsed,
	})

	if compiler.Failed() {
		panic(compiler.Errors)
	}
}

type OpaInput struct {
	Token     string
	Operation string
	Resource  string
}

func checkOpaPolicy(input OpaInput) (result bool) {
	defer track(time.Now(), "checkOpaPolicy()")
	reg := rego.New(
		rego.Query("allow_api_call = data.apigw.decision"),
		rego.Store(store),
		rego.Compiler(compiler),
	)
	query, err := reg.PrepareForEval(ctx)
	if err != nil {
		panic(err)
	}

	// Execute the prepared query.
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		panic(err)
	}
	log.Printf("Result: [%+v]", rs[0].Bindings["allow_api_call"])
	resultMap := rs[0].Bindings["allow_api_call"].(map[string]interface{})
	result = util.Compare(resultMap["allow"].(bool), true) == 0
	return result
}

type HttpAPIV2Response struct {
	IsAuthorized bool `json:"isAuthorized"`
}

var sampleToken = "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"

func Handler(event events.APIGatewayV2HTTPRequest) (HttpAPIV2Response, error) {
	defer track(time.Now(), "Handler()")
	if checkOpaPolicy(OpaInput{Token: sampleToken, Operation: event.RequestContext.HTTP.Method, Resource: event.RequestContext.HTTP.Path}) {
		log.Println("OPA policy check ok - request allowed")
		return HttpAPIV2Response{IsAuthorized: true}, nil
	} else {
		log.Println("failed OPA policy check")
		return HttpAPIV2Response{IsAuthorized: false}, nil
	}

}
