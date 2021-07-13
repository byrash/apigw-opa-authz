package main

import (
	"bytes"
	"context"
	"strings"

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

func checkOpaPolicy(roleName string, resourcePath string, operation string) (result bool) {
	defer track(time.Now(), "checkOpaPolicy()")

	reg := rego.New(
		rego.Query("allow_api_call = data.apigw.allow"),
		rego.Store(store),
		rego.Compiler(compiler),
	)
	query, err := reg.PrepareForEval(ctx)
	if err != nil {
		panic(err)
	}
	// TODO: Create input from request
	var input interface{}
	// dec := json.NewDecoder(os.Stdin)
	// dec.UseNumber()
	// if err := dec.Decode(&input); err != nil {
	// 	panic(err)
	// }

	// Execute the prepared query.
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		panic(err)
	}
	log.Printf("Result: [%+v]", rs[0].Bindings["allow_api_call"])
	result = util.Compare(rs[0].Bindings["allow_api_call"], true) == 0
	return result
}

func Handler(event events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	defer track(time.Now(), "Handler()")
	log.Println("handle event")

	/**
	check Authorization header first - just using 'allow' and 'deny' value to simulate for now
	JWT validation can replace this to check signing/exp, and then auth caching can be enabled in apigw
	*/
	var headerCheckOk = false
	switch token := strings.ToLower(event.Headers["Authorization"]); token {
	case "allow":
		log.Println("Auth header forcing allow, on to OPA check..")
		headerCheckOk = true
	case "deny":
		log.Println("Auth header forcing deny")
		return generateIAMPolicy("user", "Deny", event.MethodArn), nil
	default:
		log.Println("Auth header invalid: ", token)
		return generateIAMPolicy("user", "Deny", event.MethodArn), nil
	}

	/**
	check request against OPA policy - force the role to either 'gold' or 'silver'
	gold = can access /gold and /silver
	silver = can access /silver but not /gold
	..any other role denied
	role would be taken from JWT claims once signing, expiry etc is verified
	*/
	roleName := event.QueryStringParameters["role"] // just using QS to test
	resourcePath := event.Path
	log.Println("roleName: ", roleName)
	log.Println("resourcePath: ", resourcePath)
	if headerCheckOk && checkOpaPolicy(roleName, resourcePath, event.HTTPMethod) {
		log.Println("OPA policy check ok - request allowed")
		return generateIAMPolicy("user", "Allow", event.MethodArn), nil
	} else {
		log.Println("failed OPA policy check")
		return generateIAMPolicy("user", "Deny", event.MethodArn), nil
	}

}

/**
Generate IAM policy document
*/
func generateIAMPolicy(principalId string, effect string, resource string) events.APIGatewayCustomAuthorizerResponse {
	defer track(time.Now(), "generateIAMPolicy()")
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	authResponse.Context = map[string]interface{}{}
	return authResponse
}
