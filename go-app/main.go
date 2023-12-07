// OBP Load Test

// This script exercises the OBP Metrics and Resource Doc endpoints.

// Run with:
// go run main.go -obpapihost http://127.0.0.1:8080 -username YOUR USERNAME -password haGdju%YOUR PASSWORD -consumer YOUR CONSUMER KEY -maxOffsetMetrics 5 -maxLimitMetrics 5 -apiexplorerhost https://apiexplorer-ii-sandbox.openbankproject.com -loopResourceDocs 10 -printResourceDocs 1 -loopCreateDynamicEndpoints 5

// This script will try and grant entitlements to your user and then GET Metrics with different pagination to cause lots of cache misses.
// One way to ensure this works - is to add your User ID to the OBP API Props super_admin_user_ids, else, grant yourself CanCreateEntitlementAtAnyBank manually and then the rest should work.

// This script will print your user_id as a helper.
// maxOffsetMetrics and maxLimitMetrics affect the number of iterations that will run and the pagination values.
// loopResourceDocs will affect the number of iterations getting Resource Docs.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

// 	"cloud.google.com/go/bigquery"

// Metric represents the structure of the "metrics" array element in the JSON
type Metric struct {
	UserID                       string    `json:"user_id"`
	URL                          string    `json:"url"`
	Date                         time.Time `json:"date"`
	UserName                     string    `json:"user_name"`
	AppName                      string    `json:"app_name"`
	DeveloperEmail               string    `json:"developer_email"`
	ImplementedByPartialFunction string    `json:"implemented_by_partial_function"`
	ImplementedInVersion         string    `json:"implemented_in_version"`
	ConsumerID                   string    `json:"consumer_id"`
	Verb                         string    `json:"verb"`
	CorrelationID                string    `json:"correlation_id"`
	Duration                     int       `json:"duration"`
	SourceIP                     string    `json:"source_ip"`
	TargetIP                     string    `json:"target_ip"`
	ResponseBody                 string    `json:"response_body"`
}

// MetricsWrapper represents the structure of the root JSON object
type MetricsWrapper struct {
	Metrics []Metric `json:"metrics"`
}

// Item represents a row item.
type Item struct {
	Name string
	Age  int
}

// Save implements the ValueSaver interface.
// This example disables best-effort de-duplication, which allows for higher throughput.
// func (i *Item) Save() (map[string]bigquery.Value, string, error) {
// 	return map[string]bigquery.Value{
// 		"full_name": i.Name,
// 		"age":       i.Age,
// 	}, bigquery.NoDedupeID, nil
// }

// insertRows demonstrates inserting data into a table using the streaming insert mechanism.
// func insertRows(projectID, datasetID, tableID string) error {
// 	// projectID := "my-project-id"
// 	// datasetID := "mydataset"
// 	// tableID := "mytable"
// 	ctx := context.Background()
// 	client, err := bigquery.NewClient(ctx, projectID)
// 	if err != nil {
// 		return fmt.Errorf("bigquery.NewClient: %w", err)
// 	}
// 	defer client.Close()

// 	inserter := client.Dataset(datasetID).Table(tableID).Inserter()
// 	items := []*Item{
// 		// Item implements the ValueSaver interface.
// 		{Name: "Phred Phlyntstone", Age: 32},
// 		{Name: "Wylma Phlyntstone", Age: 29},
// 	}
// 	if err := inserter.Put(ctx, items); err != nil {
// 		return err
// 	}
// 	return nil
// }

// declaring a struct
type DirectLoginToken struct {
	// defining struct variables note: struct needs Proper case field names
	Token string `json:"token"`
}

type CurrentUserId struct {
	UserId string `json:"user_id"`
}

type Entitlement struct {
	BankID   string `json:"bank_id"`
	RoleName string `json:"role_name"`
}

type HostedBy struct {
	Organisation        string `json:"organisation"`
	Email               string `json:"email"`
	Phone               string `json:"phone"`
	OrganisationWebsite string `json:"organisation_website"`
}

type HostedAt struct {
	Organisation        string `json:"organisation"`
	OrganisationWebsite string `json:"organisation_website"`
}

type EnergySource struct {
	Organisation        string `json:"organisation"`
	OrganisationWebsite string `json:"organisation_website"`
}

type root struct {
	Version                  string       `json:"version"`
	VersionStatus            string       `json:"version_status"`
	GitCommit                string       `json:"git_commit"`
	Stage                    string       `json:"stage"`
	Connector                string       `json:"connector"`
	Hostname                 string       `json:"hostname"`
	LocalIdentityProvider    string       `json:"local_identity_provider"`
	HostedBy                 HostedBy     `json:"hosted_by"`
	HostedAt                 HostedAt     `json:"hosted_at"`
	EnergySource             EnergySource `json:"energy_source"`
	ResourceDocsRequiresRole bool         `json:"resource_docs_requires_role"`
}

type ImplementedBy struct {
	Version  string `json:"version"`
	Function string `json:"function"`
}

type ExampleRequestBody struct {
	JsonString string `json:"jsonString"`
}

type SuccessResponseBody struct {
	JsonString string `json:"jsonString"`
}

type TypedRequestBody struct {
	Type       string `json:"type"`
	Properties struct {
		JsonString struct {
			Type string `json:"type"`
		} `json:"properties"`
	} `json:"properties"`
}

type TypedSuccessResponseBody struct {
	Type       string `json:"type"`
	Properties struct {
		JsonString struct {
			Type string `json:"type"`
		} `json:"properties"`
	} `json:"properties"`
}

type Role struct {
	Role           string `json:"role"`
	RequiresBankID bool   `json:"requires_bank_id"`
}

type ResourceDoc struct {
	OperationID         string        `json:"operation_id"`
	ImplementedBy       ImplementedBy `json:"implemented_by"`
	RequestVerb         string        `json:"request_verb"`
	RequestURL          string        `json:"request_url"`
	Summary             string        `json:"summary"`
	Description         string        `json:"description"`
	DescriptionMarkdown string        `json:"description_markdown"`
	//ExampleRequestBody  ExampleRequestBody `json:"example_request_body"`
	//SuccessResponseBody      SuccessResponseBody      `json:"success_response_body"`
	ErrorResponseBodies      []string                 `json:"error_response_bodies"`
	Tags                     []string                 `json:"tags"`
	TypedRequestBody         TypedRequestBody         `json:"typed_request_body"`
	TypedSuccessResponseBody TypedSuccessResponseBody `json:"typed_success_response_body"`
	Roles                    []Role                   `json:"roles"`
	IsFeatured               bool                     `json:"is_featured"`
	SpecialInstructions      string                   `json:"special_instructions"`
	SpecifiedURL             string                   `json:"specified_url"`
	ConnectorMethods         []interface{}            `json:"connector_methods"`
}

type ResourceDocs struct {
	ResourceDocs []ResourceDoc `json:"resource_docs"`
}

/////

// //////// Swagger related //////////////////
type Info struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type Property struct {
	Type    string `json:"type"`
	Example string `json:"example"`
}

type BankAccount struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
}

type Responses struct {
	Description string `json:"description"`
	Schema      struct {
		Ref string `json:"$ref"`
	} `json:"schema"`
}

type PathItem struct {
	OperationId string   `json:"operationId"`
	Produces    []string `json:"produces"`
	Responses   map[string]Responses
	Consumes    []string `json:"consumes"`
	Description string   `json:"description"`
	Summary     string   `json:"summary"`
}

type Swagger struct {
	Swagger     string                 `json:"swagger"`
	Info        Info                   `json:"info"`
	Definitions map[string]BankAccount `json:"definitions"`
	Paths       map[string]map[string]PathItem
	Host        string   `json:"host"`
	Schemes     []string `json:"schemes"`
}

func getSwagger(modifier string) Swagger {

	// Create Info struct
	info := Info{
		Title:   fmt.Sprintf("Bank Accounts (Dynamic Endpoint) %s", modifier),
		Version: "1.0.0",
	}

	// Create Property struct
	// property := Property{
	// 	Type:    "string",
	// 	Example: "family account",
	// }

	// Create BankAccount struct
	bankAccount := BankAccount{
		Type: "object",
		Properties: map[string]Property{
			"account_name": {
				Type:    "string",
				Example: "family account",
			},
			"account_balance": {
				Type:    "string",
				Example: "1000.01",
			},
		},
	}

	// Create Responses struct
	responses := Responses{
		Description: "Success Response",
		Schema: struct {
			Ref string `json:"$ref"`
		}{
			Ref: "#/definitions/AnAccount",
		},
	}

	// Create PathItem struct for POST /accounts
	postAccount := PathItem{
		OperationId: fmt.Sprintf("%s_%s", modifier, "POST_account"),
		Produces:    []string{"application/json"},
		Responses: map[string]Responses{
			"201": responses,
		},
		Consumes:    []string{"application/json"},
		Description: "POST Accounts",
		Summary:     "POST Accounts",
	}

	// Create PathItem struct for GET /accounts/{account_id}
	getAccount := PathItem{
		OperationId: fmt.Sprintf("%s_%s", modifier, "GET_account"),
		Produces:    []string{"application/json"},
		Responses: map[string]Responses{
			"200": responses,
		},
		Consumes:    []string{"application/json"},
		Description: "Get Bank Account",
		Summary:     "Get Bank Account by Id",
	}

	// Create Paths map
	paths := map[string]map[string]PathItem{
		fmt.Sprintf("/%s%s", modifier, "/accounts"): {
			"post": postAccount,
		},
		fmt.Sprintf("/%s%s", modifier, "/accounts/{account_id}"): {
			"get": getAccount,
		},
	}

	// Create Swagger struct
	mySwagger := Swagger{
		Swagger: "2.0",
		Info:    info,
		Definitions: map[string]BankAccount{
			"AnAccount": bankAccount,
		},
		Paths:   paths,
		Host:    "obp_mock",
		Schemes: []string{"http", "https"},
	}

	return mySwagger

}

// End Swagger related /////////////////////////////

/*

{
    "resource_docs": [
        {
            "operation_id": "OBPv1.4.0-testResourceDoc",
            "implemented_by": {
                "version": "OBPv1.4.0",
                "function": "testResourceDoc"
            },
            "request_verb": "GET",
            "request_url": "/dummy",
            "summary": "Test Resource Doc",
            "description": "<p>I am only a test Resource Doc</p>\n<p>Authentication is Mandatory</p>\n<p><strong>JSON response body fields:</strong></p>\n",
            "description_markdown": "I am only a test Resource Doc\n\nAuthentication is Mandatory\n\n\n**JSON response body fields:**\n\n\n",
            "example_request_body": {
                "jsonString": "{}"
            },
            "success_response_body": {
                "jsonString": "{}"
            },
            "error_response_bodies": [
                "OBP-50000: Unknown Error.",
                "OBP-20001: User not logged in. Authentication is required!",
                "OBP-20006: User is missing one or more roles: "
            ],
            "tags": [
                "Documentation"
            ],
            "typed_request_body": {
                "type": "object",
                "properties": {
                    "jsonString": {
                        "type": "string"
                    }
                }
            },
            "typed_success_response_body": {
                "type": "object",
                "properties": {
                    "jsonString": {
                        "type": "string"
                    }
                }
            },
            "roles": [
                {
                    "role": "CanGetCustomers",
                    "requires_bank_id": true
                }
            ],
            "is_featured": false,
            "special_instructions": "",
            "specified_url": "",
            "connector_methods": []
        }
    ]
}

*/

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func main() {

	rand.Seed(time.Now().UnixNano())

	var obpApiHost string
	var username string
	var password string
	var consumerKey string
	var apiExplorerHost string

	var maxOffsetMetrics int
	var maxLimitMetrics int

	var loopResourceDocs int
	var loopCreateDynamicEndpoints int

	var tags string
	var printResourceDocs int

	flag.StringVar(&obpApiHost, "obpapihost", "YOUR OBP HOST", "Provide an OBP host to test (include the protocol and port)")
	flag.StringVar(&username, "username", "YOUR USERNAME", "Username to access the service with")
	flag.StringVar(&password, "password", "YOUR PASSWORD", "Provide your password")
	flag.StringVar(&consumerKey, "consumer", "YOUR CONSUMER KEY", "Provide your consumer key")
	flag.StringVar(&apiExplorerHost, "apiexplorerhost", "API EXPLORER II HOST", "Provide API Explorer II for documentation links ")
	flag.StringVar(&tags, "tags", "", "Provide Resource Doc tags")

	flag.IntVar(&maxOffsetMetrics, "maxOffsetMetrics", 10, "Provide your maxOffsetMetrics")
	flag.IntVar(&maxLimitMetrics, "maxLimitMetrics", 5, "Provide your maxLimitMetrics")

	flag.IntVar(&loopResourceDocs, "loopResourceDocs", 5, "Provide your loopResourceDocs")
	flag.IntVar(&loopCreateDynamicEndpoints, "loopCreateDynamicEndpoints", 5, "Provide your loopCreateDynamicEndpoints")

	flag.IntVar(&printResourceDocs, "printResourceDocs", 0, "Print the found Resource Docs (1) or not (0)")

	flag.Parse()

	fmt.Printf("I'm using the following values for -obpapihost -username -password -consumer -maxOffsetMetrics -maxLimitMetrics -apiexplorerhost -loopResourceDocs -printResourceDocs \n")
	fmt.Println(obpApiHost)
	fmt.Println(username)
	fmt.Println(password)
	fmt.Println(consumerKey)

	fmt.Println(maxOffsetMetrics)
	fmt.Println(maxLimitMetrics)

	fmt.Println(apiExplorerHost)

	fmt.Println(loopResourceDocs)
	fmt.Println(loopCreateDynamicEndpoints)

	fmt.Println(printResourceDocs)

	// Get a DirectLogin token with our credentials
	myToken, dlTokenError := getDirectLoginToken(obpApiHost, username, password, consumerKey)

	if dlTokenError == nil {
		fmt.Printf("DirectLogin token i got: %s\n", myToken)

		myRoot, errRoot := getRoot(obpApiHost, myToken)

		if errRoot == nil {
			fmt.Printf("gitCommitOfApi is: %s\n", myRoot.GitCommit)
		} else {
			fmt.Printf("errRoot: %s\n", errRoot)
		}

		createEntitlements(obpApiHost, myToken)

		// Issue many GET requests with different query parameters so we cause cache misses and thus exersise the database.
		// Minimum maxOffsetMetrics and maxLimitMetrics should be 1
		for o := 0; o <= maxOffsetMetrics; o = o + 1 {
			for l := 1; l <= maxLimitMetrics; l = l + 1 {
				getMetrics(obpApiHost, myToken, o, l)
				// Get it a second time, should hit any cache.
				getMetrics(obpApiHost, myToken, o, l)
			}
		}

		loopDynamicEndpoints(obpApiHost, myToken, loopCreateDynamicEndpoints)

		getVariousResourceDocs(obpApiHost, myToken, apiExplorerHost, tags, loopResourceDocs, printResourceDocs)

		getDynamicMessageDocs(obpApiHost, myToken, loopResourceDocs, apiExplorerHost)

	} else {
		fmt.Printf("Hmm, getDirectLoginToken returned an error: %s - I will stop now. \n", dlTokenError)
	}

}

func loopDynamicEndpoints(obpApiHost string, myToken string, loopCreateDynamicEndpoints int) {

	for i := 1; i <= loopCreateDynamicEndpoints; i++ {
		var modifier string = randSeq(10)
		createDynamicEndpoints(obpApiHost, myToken, modifier)
	}
}

func getVariousResourceDocs(obpApiHost string, myToken string, apiExplorerHost string, tags string, loopResourceDocs int, printResourceDocs int) {
	for i := 1; i <= loopResourceDocs; i++ {
		myRDCount, myRDError := getResourceDocs(obpApiHost, myToken, i, "static", apiExplorerHost, tags, printResourceDocs)

		if myRDError == nil {
			fmt.Printf("we got %d resource docs \n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs \n", myRDError)
		}

		if myRDError == nil {
			fmt.Printf("we got %d resource docs \n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}

		myRDCount, myRDError = getResourceDocs(obpApiHost, myToken, i, "dynamic", apiExplorerHost, tags, printResourceDocs)

		if myRDError == nil {
			fmt.Printf("we got %d resource docs\n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}

		if myRDError == nil {
			fmt.Printf("we got %d resource docs\n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}

		myRDCount, myRDError = getResourceDocs(obpApiHost, myToken, i, "all", apiExplorerHost, tags, printResourceDocs)

		if myRDError == nil {
			fmt.Printf("we got %d resource docs\n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}
	}

}

func getDirectLoginToken(obpApiHost string, username string, password string, consumerKey string) (string, error) {

	// defining a struct instance, we will put the token in this.
	var directLoginToken1 DirectLoginToken

	// Create client
	client := &http.Client{}

	// Create request path
	requestURL := fmt.Sprintf("%s/my/logins/direct", obpApiHost)

	// Nothing in the body
	req, err1 := http.NewRequest("POST", requestURL, nil)

	// Header
	//DirectLoginHeaderValue := fmt.Sprintf("username=%s, password=%s, consumer_key=%s", username, password, consumerKey)
	//fmt.Printf("DirectLoginHeaderValue : %s\n", DirectLoginHeaderValue)

	// Headers
	//req.Header.Add("DirectLogin", DirectLoginHeaderValue)
	//req.Header.Add("Content-Type", "application/json")

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("username=%s, password=%s, consumer_key=%s", username, password, consumerKey)},
	}

	// Do the Request
	resp, err1 := client.Do(req)

	// var j interface{}
	// var err = json.NewDecoder(resp.Body).Decode(&j)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("%s", j)

	if err1 == nil {
		fmt.Println("We got a response from the http server. Will check Response Status Code...")
	} else {
		fmt.Println("We failed making the http request: ", err1)
		return "", err1
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 201 {
		fmt.Printf("We got a 201 Response: %d \n", resp.StatusCode)
	} else {
		fmt.Printf("Hmm, Non ideal Response Status : %s \n", resp.Status)
		fmt.Printf("Response Body : %s \n", string(respBody))
		return "", errors.New("Non 201 Response")
	}

	//fmt.Println("response Headers : ", resp.Header)

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	err2 := json.Unmarshal(respBody, &directLoginToken1)

	if err2 == nil {
		//fmt.Printf("I will return this token: %s \n", directLoginToken1.Token)
		return directLoginToken1.Token, nil
	} else {
		fmt.Printf("Struct instance is: %s", directLoginToken1)
		fmt.Printf("token is %s \n", directLoginToken1.Token)
		return "", err2
	}

}

func getUserId(obpApiHost string, token string) (string, error) {

	fmt.Printf("Hello from getUserId. obpApiHost is: %s token is %s \n", obpApiHost, token)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var currentUserId CurrentUserId

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/current/user_id", obpApiHost)
	//requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/current", obpApiHost)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure constructing NewRequest: ", erry)
	}

	//var hardCodedToken = "eyJhbGciOiJIUzI1NiJ9.eyIiOiIifQ.Bk5ubGsnLHkyH-R4UOv-fS5oJULczUF-qcQglV_nhLY"

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("***** Failure trying to get user_id: ", err1)
	}

	// This approach to setting DirectLogin header does not seem to work
	//DirectLoginHeaderValue := fmt.Sprintf("token=%s", token)
	// req.Header.Set("DirectLogin", fmt.Sprintf("token=%s", token))
	// req.Header.Set("Content-Type", "application/json")

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	//fmt.Println("getUserId response Status : ", resp.Status)
	//fmt.Println("response Headers : ", resp.Header)
	//fmt.Println("getUserId response Body : ", string(respBody))

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	err2 := json.Unmarshal(respBody, &currentUserId)

	if err2 != nil {
		fmt.Println(err2)
	}

	//fmt.Println("Struct instance for currentUserId is:", currentUserId)
	//fmt.Printf("UserId is %s \n", currentUserId.UserId)

	return currentUserId.UserId, err2

}

//

func createEntitlements(obpApiHost string, token string) error {

	//fmt.Printf("token i will use: %s\n", token)
	// We need the User ID to grant entitlements.
	userId, error := getUserId(obpApiHost, token)

	if error == nil {
		fmt.Printf("userId is: %s \n", userId)
		// If we are a super user we can grant ourselves this
		error := createEntitlement(obpApiHost, token, userId, "", "CanCreateEntitlementAtAnyBank")
		// Then with the above role we can grant ourselves other roles
		if error == nil {
			error := createEntitlement(obpApiHost, token, userId, "", "CanReadMetrics")
			if error == nil {
				error := createEntitlement(obpApiHost, token, userId, "", "CanReadAggregateMetrics")
				if error == nil {
					error := createEntitlement(obpApiHost, token, userId, "", "CanCreateDynamicEndpoint")
					if error == nil {
						error := createEntitlement(obpApiHost, token, userId, "", "CanGetAllDynamicMessageDocs")
						if error == nil {
							error := createEntitlement(obpApiHost, token, userId, "", "CanCreateDynamicMessageDoc")
							if error == nil {
								fmt.Println("createEntitlements says: No errors")
							} else {
								fmt.Printf("createEntitlements says error: %s\n", error)
							}
						} else {
							fmt.Printf("createEntitlements says error: %s\n", error)
						}
					} else {
						fmt.Printf("createEntitlements says error: %s\n", error)
					}
				} else {
					fmt.Printf("createEntitlements says error: %s\n", error)
				}
			} // note these missing message on error
		}
	}

	//

	return error

}

func createEntitlement(obpApiHost string, token string, userID string, bankId string, roleName string) error {

	// Create client
	client := &http.Client{}

	// Create request

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/%s/entitlements", obpApiHost, userID)

	entitlement := Entitlement{
		BankID:   bankId,
		RoleName: roleName,
	}
	// marshall data to json (like json_encode)
	marshalledEntitlement, err := json.Marshal(entitlement)
	if err != nil {
		fmt.Printf("impossible to marshall entitlement: %s", err)
	}

	req, errx := http.NewRequest("POST", requestURL, bytes.NewReader(marshalledEntitlement))

	if errx != nil {
		fmt.Println("Failure : ", errx)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("Failure : ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	//fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody))

	return err1

}

func createDynamicEndpoints(obpApiHost string, token string, modifier string) error {

	// Create client
	client := &http.Client{}

	// Create request

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/management/dynamic-endpoints", obpApiHost)
	/*
		jsonStr := `{
			"swagger": "2.0",
			"info": {
				"title": "Bank Accounts (Dynamic Endpoint)",
				"version": "1.0.0"
			},
			"definitions": {
				"AnAccount": {
					"type": "object",
					"properties": {
						"account_name": {
							"type": "string",
							"example": "family account"
						},
						"account_balance": {
							"type": "string",
							"example": "1000.01"
						}
					}
				}
			},
			"paths": {
				"/accounts": {
					"post": {
						"operationId": "POST_account",
						"produces": [
							"application/json"
						],
						"responses": {
							"201": {
								"description": "Success Response",
								"schema": {
									"$ref": "#/definitions/AnAccount"
								}
							}
						},
						"consumes": [
							"application/json"
						],
						"description": "POST Accounts",
						"summary": "POST Accounts"
					}
				},
				"/accounts/{account_id}": {
					"get": {
						"operationId": "GET_account",
						"produces": [
							"application/json"
						],
						"responses": {
							"200": {
								"description": "Success Response",
								"schema": {
									"$ref": "#/definitions/AccountName"
								}
							}
						},
						"consumes": [
							"application/json"
						],
						"description": "Get Bank Account",
						"summary": "Get Bank Account by Id"
					}
				}
			},
			"host": "obp_mock",
			"schemes": [
				"http",
				"https"
			]
		}`

	*/

	// var swaggerData Swagger

	// var modifier string = randSeq(10)

	// // Load the json string into an instance of a struct
	// err := json.Unmarshal([]byte(jsonStr), &swaggerData)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// } else {
	// 	fmt.Println("Unmarshal of json into struct instance  seems ok")
	// }

	swaggerData := getSwagger(modifier)

	fmt.Println("Swagger Version:", swaggerData.Swagger)
	fmt.Println("Info Title:", swaggerData.Info.Title)
	fmt.Println("Info Version:", swaggerData.Info.Version)
	fmt.Println("Host:", swaggerData.Host)
	fmt.Println("Schemes:", swaggerData.Schemes)
	fmt.Println("Definitions:", swaggerData.Definitions)
	fmt.Println("Paths:", swaggerData.Paths)

	// Set a new title

	/*
		swaggerData.Info.Title = fmt.Sprintf("%s - %s", swaggerData.Info.Title, modifier)

		fmt.Printf("Here is the updated title\n")

		fmt.Printf("%+v\n", swaggerData.Info.Title)

		fmt.Printf("Here are Paths......\n")

		fmt.Printf("%+v\n", swaggerData.Paths)

		for key, val := range swaggerData.Paths {
			fmt.Printf("key is: %+v val is: %+v\n", key, val)

			// note postThing is a COPY
			postThing, ok := val["post"]
			// If the key exists
			if ok {
				// Do something
				originalOperationId := postThing.OperationId
				fmt.Printf("postThing.originalOperationId: %+v \n", originalOperationId)

				postThing.OperationId = fmt.Sprintf("%s_%s", modifier, originalOperationId)

				// hmm can't change this in place?
				//val["post"].OperationId = fmt.Sprintf("%s_%s", modifier, originalOperationId)

				fmt.Printf("postThing.OperationId is now: %+v \n", postThing.OperationId)
			} else {
				fmt.Println("could not get postThing")
			}

			getThing, ok := val["get"]
			// If the key exists
			if ok {
				// Do something
				originalOperationId := getThing.OperationId
				fmt.Printf("getThing.originalOperationId: %+v \n", originalOperationId)
				getThing.OperationId = fmt.Sprintf("%s_%s", modifier, originalOperationId)

				fmt.Printf("getThing.OperationId is now: %+v \n", getThing.OperationId)
			} else {
				fmt.Println("could not get getThing")
			}

			fmt.Printf("get of val is : %+v\n", val["get"])
			fmt.Printf("put of val is : %+v\n", val["put"])
			fmt.Printf("delete of val is : %+v\n", val["delete"])
			fmt.Printf("head of val is : %+v\n", val["head"])

		}

		fmt.Printf("Here are Paths as we process......\n")

		// Add a random prefix to every path. The path is a key.
		for key, val := range swaggerData.Paths {

			// assume paths are unique to start with so we can use a static modifier
			newKey := fmt.Sprintf("/%s%s", modifier, key)

			fmt.Println(newKey)

			swaggerData.Paths[newKey] = val

			delete(swaggerData.Paths, key)

		}

		fmt.Printf("Here are Paths after Modification......\n")

		for key, val := range swaggerData.Paths {
			fmt.Println(key, val)

		}

		fmt.Printf("...... Done ......\n")
	*/

	// Convert the struct to json
	swaggerJson, err := json.Marshal(swaggerData)
	if err != nil {
		fmt.Printf("impossible to marshall swagger: %s", err)
	} else {
		fmt.Println("Marshalled data into json ok")
	}

	req, errx := http.NewRequest("POST", requestURL, bytes.NewReader(swaggerJson))

	if errx != nil {
		fmt.Println("Failure creating NewRequest: ", errx)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	fmt.Println("Before creating resource doc : ")

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("****** Failure creating resource docs : ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	//fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody))

	return err1

}

func getMetrics(obpApiHost string, token string, offset int, limit int) (string, error) {

	fmt.Println(fmt.Sprintf("hello from getMetrics offset is %d, limit is %d ", offset, limit))

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var currentUserId CurrentUserId

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/management/metrics?offset=%d&limit=%d", obpApiHost, offset, limit)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure : ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	before := time.Now()

	// Fetch Request
	resp, err1 := client.Do(req)

	after := time.Now()

	duration := after.Sub(before)

	if err1 != nil {
		fmt.Println("***** Failure when getting Metrics: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("getMetrics response Status : ", resp.Status)

	fmt.Println(fmt.Sprintf("getMetrics response Status was %s, offset was %d, limit was %d duration was %s", resp.Status, offset, limit, duration))

	//fmt.Println("response Headers : ", resp.Header)

	if resp.StatusCode != 200 {
		fmt.Println("getMetrics response Body : ", string(respBody))
		fmt.Println(fmt.Sprintf("offset was %d", offset))
		fmt.Println(fmt.Sprintf("limit was %d", limit))
	} else {

		// Unmarshal JSON into the struct
		var metricsWrapper MetricsWrapper
		err := json.Unmarshal([]byte(respBody), &metricsWrapper)
		if err != nil {
			fmt.Println("Error:", err)
		}

		// Accessing the data

		metrics := metricsWrapper.Metrics

		fmt.Println(fmt.Sprintf("Here are the %d Metrics records:", len(metrics)))

		for _, metric := range metrics {
			fmt.Printf("User ID: %s\n", metric.UserID)
			fmt.Printf("URL: %s\n", metric.URL)
			fmt.Printf("Date: %s\n", metric.Date)
			fmt.Printf("User Name: %s\n", metric.UserName)
			fmt.Printf("App Name: %s\n", metric.AppName)
			fmt.Printf("Developer Email: %s\n", metric.DeveloperEmail)
			fmt.Printf("Implemented By Partial Function: %s\n", metric.ImplementedByPartialFunction)
			fmt.Printf("Implemented In Version: %s\n", metric.ImplementedInVersion)
			fmt.Printf("Consumer ID: %s\n", metric.ConsumerID)
			fmt.Printf("Verb: %s\n", metric.Verb)
			fmt.Printf("Correlation ID: %s\n", metric.CorrelationID)
			fmt.Printf("Duration: %d\n", metric.Duration)
			fmt.Printf("Source IP: %s\n", metric.SourceIP)
			fmt.Printf("Target IP: %s\n", metric.TargetIP)
			fmt.Printf("Response Body: %s\n", metric.ResponseBody)
		}

	}

	//fmt.Println("getMetrics response Body : ", string(respBody))

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	//err2 := json.Unmarshal(respBody, &currentUserId)

	//if err2 != nil {
	//		fmt.Println(err2)
	//	}

	//	fmt.Println("Struct instance for currentUserId is:", currentUserId)
	//	fmt.Printf("UserId is %s \n", currentUserId.UserId)

	return currentUserId.UserId, nil

}

func getRoot(obpApiHost string, token string) (root, error) {

	fmt.Printf("Hello from getRoot. obpApiHost is: %s token is %s \n", obpApiHost, token)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var myRoot root

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/root", obpApiHost)
	//requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/current", obpApiHost)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure constructing NewRequest: ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("***** Failure trying to getRoot: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	err2 := json.Unmarshal(respBody, &myRoot)

	if err2 != nil {
		fmt.Println(err2)
		fmt.Println("Struct instance for myRoot is:", myRoot)
	} else {
		// fmt.Printf("GitCommit is %s \n", myRoot.GitCommit)
	}

	fmt.Printf("------ Here are the Response Headers for : %s -------- \n", requestURL)
	for k, v := range resp.Header {
		fmt.Print(k)
		fmt.Print(" : ")
		fmt.Println(v)
	}
	fmt.Println("------- End of Response Headers --------")

	return myRoot, err2

}

func getResourceDocs(obpApiHost string, token string, tryCount int, content string, apiExplorerHost string, tags string, printResourceDocs int) (int, error) {

	fmt.Println("Hello from getResourceDocs. Using obpApiHost: ", obpApiHost)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var myResourceDocs ResourceDocs

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/resource-docs/OBPv5.1.0/obp?tags=%s&content=%s", obpApiHost, tags, content)

	//requestURL := fmt.Sprintf("%s/obp/v5.1.0/resource-docs/OBPv5.0.0/obp?tags=%s&content=%s", obpApiHost, tags, content)

	fmt.Println("requestURL : ", requestURL)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure : ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	before := time.Now()

	// Fetch Request
	resp, err1 := client.Do(req)

	after := time.Now()

	duration := after.Sub(before)

	if err1 != nil {
		fmt.Println("***** Failure when getting Resource Docs: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("getResourceDocs response Status : ", resp.Status)

	fmt.Println(fmt.Sprintf("getResourceDocs response Status was %s, duration was %s, tryCount was %d, content was %s ", resp.Status, duration, tryCount, content))

	if resp.StatusCode != 200 {
		fmt.Println("getResourceDocs response Body : ", string(respBody))
		fmt.Println(fmt.Sprintf("tryCount was %d", tryCount))
		fmt.Println(fmt.Sprintf("content was %s", content))
	}

	err2 := json.Unmarshal(respBody, &myResourceDocs)

	if err2 != nil {
		fmt.Println(err2)
	}

	/* Example data for testing


	jsonData := `{
	    "resource_docs": [
	        {
	            "operation_id": "OBPv1.4.0-testResourceDoc",
	            "implemented_by": {
	                "version": "OBPv1.4.0",
	                "function": "testResourceDoc"
	            },
	            "request_verb": "GET",
	            "request_url": "/dummy",
	            "summary": "Test Resource Doc",
	            "description": "<p>I am only a test Resource Doc</p>\n<p>Authentication is Mandatory</p>\n<p><strong>JSON response body fields:</strong></p>\n",
	            "description_markdown": "I am only a test Resource Doc\n\nAuthentication is Mandatory\n\n\n**JSON response body fields:**\n\n\n",
	            "example_request_body": {
	                "jsonString": "{}"
	            },
	            "success_response_body": {
	                "jsonString": "{}"
	            },
	            "error_response_bodies": [
	                "OBP-50000: Unknown Error.",
	                "OBP-20001: User not logged in. Authentication is required!",
	                "OBP-20006: User is missing one or more roles: "
	            ],
	            "tags": [
	                "Documentation"
	            ],
	            "typed_request_body": {
	                "type": "object",
	                "properties": {
	                    "jsonString": {
	                        "type": "string"
	                    }
	                }
	            },
	            "typed_success_response_body": {
	                "type": "object",
	                "properties": {
	                    "jsonString": {
	                        "type": "string"
	                    }
	                }
	            },
	            "roles": [
	                {
	                    "role": "CanGetCustomers",
	                    "requires_bank_id": true
	                }
	            ],
	            "is_featured": false,
	            "special_instructions": "",
	            "specified_url": "",
	            "connector_methods": []
	        }
	    ]
	}`
	*/

	if printResourceDocs == 1 { // Trying to use bool here was ugly

		for i := 0; i < len(myResourceDocs.ResourceDocs); i++ {
			//fmt.Printf(" OperationID: %s Summary: %s \n", myResourceDocs.ResourceDocs[i].OperationID, myResourceDocs.ResourceDocs[i].Summary)

			fmt.Printf("[%s](%s/operationid/%s)\n", myResourceDocs.ResourceDocs[i].Summary, apiExplorerHost, myResourceDocs.ResourceDocs[i].OperationID)
		}

	}
	// obpApiExplorerHost

	// https://apiexplorer-ii-sandbox.openbankproject.com/operationid/OBPv4.0.0-getBankLevelEndpointTags?version=OBPv5.1.0

	return len(myResourceDocs.ResourceDocs), nil

}

// Define a struct to match the JSON structure
type DynamicMessage struct {
	OutboundAvroSchema     string      `json:"outbound_avro_schema"`
	InboundAvroSchema      string      `json:"inbound_avro_schema"`
	AdapterImplementation  string      `json:"adapter_implementation"`
	DynamicMessageDocID    string      `json:"dynamic_message_doc_id"`
	Description            string      `json:"description"`
	Process                string      `json:"process"`
	OutboundTopic          string      `json:"outbound_topic"`
	MethodBody             string      `json:"method_body"`
	MessageFormat          string      `json:"message_format"`
	ExampleOutboundMessage struct{}    `json:"example_outbound_message"`
	InboundTopic           string      `json:"inbound_topic"`
	ExampleInboundMessage  struct{}    `json:"example_inbound_message"`
	BankID                 interface{} `json:"bank_id"`
	ProgrammingLang        string      `json:"programming_lang"`
}

type DynamicMessages struct {
	DynamicMessageDocs []DynamicMessage `json:"dynamic-message-docs"`
}

func getDynamicMessageDocs(obpApiHost string, token string, tryCount int, apiExplorerHost string) (int, error) {

	fmt.Println("Hello from getDynamicMessageDocs. Using obpApiHost: ", obpApiHost)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var myDynamicMessages DynamicMessages

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/management/dynamic-message-docs", obpApiHost)

	fmt.Println("requestURL : ", requestURL)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure : ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	before := time.Now()

	// Fetch Request
	resp, err1 := client.Do(req)

	after := time.Now()

	duration := after.Sub(before)

	if err1 != nil {
		fmt.Println("***** Failure when getting getDynamicMessageDocs: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("getDynamicMessageDocs response Status : ", resp.Status)

	fmt.Println(fmt.Sprintf("getDynamicMessageDocs response Status was %s, duration was %s, tryCount was %d", resp.Status, duration, tryCount))

	if resp.StatusCode != 200 {
		fmt.Println("getDynamicMessageDocs response Body: ", string(respBody))
		fmt.Println(fmt.Sprintf("tryCount was %d", tryCount))

	}

	err2 := json.Unmarshal(respBody, &myDynamicMessages)

	if err2 != nil {
		fmt.Println(err2)
	}

	for i := 0; i < len(myDynamicMessages.DynamicMessageDocs); i++ {
		fmt.Printf(myDynamicMessages.DynamicMessageDocs[i].Process)
	}

	return len(myDynamicMessages.DynamicMessageDocs), nil

}
