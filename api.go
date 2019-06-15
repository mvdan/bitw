// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// no need for a timeout, as we use contexts.
var httpClient = &http.Client{}

type preLoginRequest struct {
	Email string `json:"email"`
}

type preLoginResponse struct {
	KDF           int
	KDFIterations int
}

func jsonPOST(ctx context.Context, urlstr string, recv, send interface{}) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(send); err != nil {
		return err
	}
	req, err := http.NewRequest("POST", urlstr, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if req.Context() == nil {
		// Set a default timeout.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req = req.WithContext(ctx)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("%s: %s", http.StatusText(res.StatusCode), body)
	}
	if err := json.NewDecoder(res.Body).Decode(recv); err != nil {
		return err
	}
	return nil
}

func queryPOST(ctx context.Context, urlstr string, recv, send url.Values) error {
	req, err := http.NewRequest("POST", urlstr, strings.NewReader(send.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if req.Context() == nil {
		// Set a default timeout.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req = req.WithContext(ctx)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("%s: %s", http.StatusText(res.StatusCode), body)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	values2, err := url.ParseQuery(string(body))
	if err != nil {
		return err
	}
	for key, value := range values2 {
		recv[key] = append(recv[key], value...)
	}
	return nil
}
