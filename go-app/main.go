// OBP Load Test

// Run with:
// go run main.go -host http://127.0.0.1:8080 -username YOUR USERNAME -password YOUR PASSWORD -consumer YOUR CONSUMER KEY -maxOffset 10 -maxLimit 5

// This script will try and grant entitlements to your user and then GET Metrics with different pagination to cause lots of cache misses.
// One way to ensure this works - is to add your User ID to the OBP API Props super_admin_user_ids, else, grant yourself CanCreateEntitlementAtAnyBank manually and then the rest should work.

// This script will print your user_id as a helper.
// maxOffset and maxLimit affect the number of iterations that will run and the pagination values.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

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

func main() {

	var obpApiHost string
	var username string
	var password string
	var consumerKey string

	var maxOffset int
	var maxLimit int

	flag.StringVar(&obpApiHost, "host", "YOUR OBP HOST", "Provide an OBP host to test (include the port if need be)")
	flag.StringVar(&username, "username", "YOUR USERNAME", "Username to access the service with")
	flag.StringVar(&password, "password", "YOUR PASSWORD", "Provide your password")
	flag.StringVar(&consumerKey, "consumer", "YOUR CONSUMER KEY", "Provide your consumer key")

	flag.IntVar(&maxOffset, "maxOffset", 10, "Provide your maxOffset")
	flag.IntVar(&maxLimit, "maxLimit", 5, "Provide your maxLimit")

	flag.Parse()

	fmt.Printf("I'm using the following values for -host -username -password -consumer -maxOffset -maxLimit \n")
	fmt.Println(obpApiHost)
	fmt.Println(username)
	fmt.Println(password)
	fmt.Println(consumerKey)

	fmt.Println(maxOffset)
	fmt.Println(maxLimit)

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
		// Minimum maxOffset and maxLimit should be 1
		for o := 1; o < maxOffset; o++ {
			for l := 1; l < maxLimit; l = l + 9 {
				getMetrics(obpApiHost, myToken, o, l)
			}
		}
	} else {
		fmt.Printf("Hmm, getDirectLoginToken returned an error: %s - I will stop now. \n", dlTokenError)
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
					fmt.Println("createEntitlements says: No errors")
				} else {
					fmt.Printf("createEntitlements says error: %s\n", error)
				}
			}
		}
	}

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

func getMetrics(obpApiHost string, token string, offset int, limit int) (string, error) {

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

	return myRoot, err2

}
