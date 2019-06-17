// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

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

func login(ctx context.Context) error {
	if email == "" {
		return fmt.Errorf("need a configured email or $EMAIL to log in")
	}

	var preLogin preLoginResponse
	if err := jsonPOST(ctx, apiURL+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return fmt.Errorf("could not pre-login: %v", err)
	}
	data.KDF = preLogin.KDF
	data.KDFIterations = preLogin.KDFIterations
	saveData = true

	if err := ensurePassword(); err != nil {
		return err
	}

	// First, we create the master key, with the password, the lowercase
	// email as salt, and the number of iterations the server told us.
	masterKey := pbkdf2.Key(password, []byte(strings.ToLower(email)),
		preLogin.KDFIterations, 32, sha256.New)

	// Then we create the hashed password, with the master key as password,
	// the password as hash, and just one iteration.
	hashedPassword := b64enc.EncodeToString(pbkdf2.Key(masterKey, password,
		1, 32, sha256.New))

	now := time.Now().UTC()
	// Now, we request an auth token.
	// For some reason, this endpoint requires url-encoded values, and won't
	// accept JSON. But of course, the response is JSON.
	var tokLogin tokLoginResponse
	err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, urlValues(
		"grant_type", "password",
		"username", email,
		"password", string(hashedPassword),
		"scope", loginScope,
		"client_id", "connector", // seen in bitwarden/jslib
		"deviceType", deviceType,
		"deviceIdentifier", data.DeviceID,
		"deviceName", deviceName,
	))
	errsc, ok := err.(*errStatusCode)
	if ok && bytes.Contains(errsc.body, []byte("TwoFactor")) {
		return fmt.Errorf("TODO: tfa")
	}
	if err != nil {
		return fmt.Errorf("could not login via password: %v", err)
	}
	data.AccessToken = tokLogin.AccessToken
	data.RefreshToken = tokLogin.RefreshToken
	data.TokenExpiry = now.Add(time.Duration(tokLogin.ExpiresIn) * time.Second)
	saveData = true
	return nil
}

func refreshToken(ctx context.Context) error {
	return nil
}

func urlValues(pairs ...string) url.Values {
	if len(pairs)%2 != 0 {
		panic("pairs must be of even length")
	}
	vals := make(url.Values)
	for i := 0; i < len(pairs); i += 2 {
		vals.Set(pairs[i], pairs[i+1])
	}
	return vals
}

var b64enc = base64.StdEncoding.Strict()
