package main

import (
	"bytes"
	"context"
	_ "embed"
	"log"
	"sync"

	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

var (
	//go:embed opa_apigw.rego
	module string
	//go:embed opa_authz_data.json
	authzData  string
	store      storage.Store
	compiler   *ast.Compiler
	validUntil time.Time
	mutex      *sync.Mutex
	logger     *log.Logger
	s3Client   *s3.Client
)

const authDataValidMin = 1

func main() {
	lambda.Start(Handler)
}

func track(start time.Time, name string) {
	elapsed := time.Since(start)
	logger.Printf("%s took %s", name, elapsed)
}

// Compile OPA policies once per container
func init() {
	defer track(time.Now(), "init()")
	logger = log.New(log.Default().Writer(), "Lambda # "+uuid.NewString()+"  -- ", log.Flags())
	parsed, err := ast.ParseModule("opa_apigw.rego", module)
	if err != nil {
		logger.Fatal(err)
	}
	compiler = ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{
		"opa_apigw.rego": parsed,
	})
	if compiler.Failed() {
		logger.Fatal(compiler.Errors)
	}
	validUntil = time.Now().Local().Add(time.Minute * authDataValidMin)
	mutex = &sync.Mutex{}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Fatal(err)
	}
	s3Client = s3.NewFromConfig(cfg)
	authzData = "" // Manually setting it to empty just to sure embeeded content doesnt exists
	authzData, err := getAuthzDataFromS3(ctx)
	if err != nil {
		logger.Fatal(err)
	}
	store = inmem.NewFromReader(bytes.NewBufferString(authzData))
}

type OpaInput struct {
	Token     string `json:"token,omitempty"`
	Operation string `json:"operation,omitempty"`
	Resource  string `json:"resource,omitempty"`
}

func getAuthzDataFromS3(ctx context.Context) (string, error) {
	defer track(time.Now(), "getAuthzDataFromS3()")
	output, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("BUCKET_NAME"),
		Key:    aws.String("AUTHZ_FILE_NAME"),
	})
	if err != nil {
		return "", err
	}
	defer output.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(output.Body)
	return buf.String(), nil
}

func getRegoQuery(ctx context.Context) (rego.PreparedEvalQuery, error) {
	defer track(time.Now(), "getRegoQuery()")
	if time.Now().Local().After(validUntil) {
		logger.Printf("Invalid Authz Data [%v]", validUntil)
		mutex.Lock()
		if time.Now().Local().After(validUntil) { // Still not valid after ?
			logger.Printf("Invalid Authz Data [%v] after aquiring lock", validUntil)
			// Store Invalid reload it
			authzData, err := getAuthzDataFromS3(ctx)
			if err != nil {
				logger.Fatal(err)
			}
			store = inmem.NewFromReader(bytes.NewBufferString(authzData))
			validUntil = time.Now().Add(time.Minute * authDataValidMin)
			logger.Println("New Authz Data Loaded")
		}
		mutex.Unlock()
	}
	reg := rego.New(
		rego.Query("allow_api_call = data.apigw.decision"),
		rego.Store(store),
		rego.Compiler(compiler),
		rego.Dump(log.Default().Writer()),
	)
	return reg.PrepareForEval(ctx)
}

func checkOpaPolicy(input OpaInput) (result bool) {
	defer track(time.Now(), "checkOpaPolicy()")
	ctx := context.Background()
	query, err := getRegoQuery(ctx)
	if err != nil {
		logger.Printf("Error [%+v]", err)
		return false
	}
	// Execute the prepared query.
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		logger.Printf("Error [%+v]", err)
		return false
	}
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
		logger.Println("OPA policy check ok - request allowed")
		return HttpAPIV2Response{IsAuthorized: true}, nil
	} else {
		logger.Println("failed OPA policy check")
		return HttpAPIV2Response{IsAuthorized: false}, nil
	}

}
