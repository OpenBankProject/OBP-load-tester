package main

import (
        "fmt"
        "net/http"
        "os"
)


const serverPort = 80

func main() {

        requestURL := fmt.Sprintf("http://apisandbox.openbankproject.com:%d", serverPort)
		fmt.Printf("requestURL: %s\n", requestURL)
        res, err := http.Get(requestURL)
        if err != nil {
                fmt.Printf("error making http request: %s\n", err)
                os.Exit(1)
        }

		fmt.Printf("client: got response!\n")
        fmt.Printf("client: status code: %d\n", res.StatusCode)

}



