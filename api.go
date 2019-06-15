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

type tokLoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"key"`
}

type twoFactorResponse struct {
	TwoFactorProviders []int
}

type errStatusCode struct {
	code int
	body []byte
}

func (e *errStatusCode) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.code), e.body)
}

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
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, recv); err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return &errStatusCode{res.StatusCode, body}
	}
	return nil
}
