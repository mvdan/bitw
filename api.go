// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{
	// Specific http calls can use lower timeouts via context.
	Timeout: 10 * time.Second,
}

type errStatusCode struct {
	code int
	body []byte
}

func (e *errStatusCode) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.code), e.body)
}

type authToken struct{}

func jsonPOST(ctx context.Context, urlstr string, recv, send interface{}) error {
	var r io.Reader
	contentType := "application/json"
	if values, ok := send.(url.Values); ok {
		// Some endpoints only accept urlencoded bodies.
		r = strings.NewReader(values.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else {
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(send); err != nil {
			return err
		}
		r = buf
	}
	req, err := http.NewRequest("POST", urlstr, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	return httpDo(ctx, req, recv)
}

func jsonGET(ctx context.Context, urlstr string, recv interface{}) error {
	req, err := http.NewRequest("GET", urlstr, nil)
	if err != nil {
		return err
	}
	return httpDo(ctx, req, recv)
}

func httpDo(ctx context.Context, req *http.Request, recv interface{}) error {
	if token, ok := ctx.Value(authToken{}).(string); ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return &errStatusCode{res.StatusCode, body}
	}
	if err := json.Unmarshal(body, recv); err != nil {
		fmt.Fprintln(os.Stderr, string(body))
		return err
	}
	return nil
}
