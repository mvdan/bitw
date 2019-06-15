// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// no need for a timeout, as we use contexts.
var httpClient = &http.Client{}

type preLogin struct {
	Email string `json:"email"`
}

type preLoginResponse struct {
	KDF           int
	KDFIterations int
}

func jsonPOST(ctx context.Context, path string, recv, send interface{}) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(send); err != nil {
		return err
	}
	req, err := http.NewRequest("POST", apiURL+path, buf)
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
		return fmt.Errorf("%s", http.StatusText(res.StatusCode))
	}
	if err := json.NewDecoder(res.Body).Decode(recv); err != nil {
		return err
	}
	return nil
}
