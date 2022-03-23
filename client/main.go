package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/proxy"
)

const (
	PROXY_URL = "127.0.0.1:7000"
	URL       = "https://www.bing.com"
)

func main() {
	// create proxy
	dialer, err := proxy.SOCKS5("tcp", PROXY_URL, nil, proxy.Direct)
	if err != nil {
		log.Fatal("crate proxy field")
	}

	// create a http client
	httpTransport := &http.Transport{}
	client := http.Client{
		Transport: httpTransport,
	}
	httpTransport.Dial = dialer.Dial
	// create a http request
	request, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		log.Fatal("create request failed")
	}

	// send request
	fmt.Println("send request to proxy server")
	response, err := client.Do(request)
	if err != nil {
		log.Fatal("request page failed:", err)
	}
	// print response
	defer response.Body.Close()
	_, err = io.Copy(os.Stdout, response.Body)
	if err != nil {
		log.Fatal("print page faile")
	}
}
