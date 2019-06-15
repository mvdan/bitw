// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const (
	deviceName = "firefox"
	deviceType = "3" // bitwarden's device type for FireFox
	loginScope = "api offline_access"
)

// TODO: move these to a config file
var (
	deviceID = uuid.New().String() // TODO: make this constant
	apiURL   = "https://api.bitwarden.com"
	idtURL   = "https://identity.bitwarden.com"

	email    = os.Getenv("EMAIL")
	password = []byte(os.Getenv("PASSWORD"))
)

func run() error {
	ctx := context.Background()

	err := login(ctx, email, password)
	if err != nil {
		return err
	}
	return nil
}

func login(ctx context.Context, email string, password []byte) error {
	var preLogin preLoginResponse
	if err := jsonPOST(ctx, apiURL+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return fmt.Errorf("could not pre-login: %v", err)
	}

	// First, we create the master key, with the password, the lowercase
	// email as salt, and the number of iterations the server told us.
	masterKey := pbkdf2.Key(password, []byte(strings.ToLower(email)),
		preLogin.KDFIterations, 32, sha256.New)

	// symmetricKey := randBytes(64)
	// encKey := symmetricKey[:32]
	// macKey := symmetricKey[32:]
	// iv := randBytes(16)

	// Then we create the hashed password, with the master key as password,
	// the password as hash, and just one iteration.
	hashedPassword := b64enc(pbkdf2.Key(masterKey, password,
		1, 32, sha256.New))

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
		"deviceIdentifier", deviceID,
		"deviceName", deviceName,
	))
	errsc, ok := err.(*errStatusCode)
	if ok && bytes.Contains(errsc.body, []byte("TwoFactor")) {
		return fmt.Errorf("TODO: tfa")
	}
	if err != nil {
		return fmt.Errorf("could not login via password: %v", err)
	}
	fmt.Printf("%#v\n", tokLogin)
	return nil
}

type urlencoded strings.Reader

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

var base64Encoding = base64.StdEncoding.Strict()

func b64enc(src []byte) []byte {
	dst := make([]byte, base64Encoding.EncodedLen(len(src)))
	base64Encoding.Encode(dst, src)
	return dst
}

func randBytes(size int) []byte {
	p := make([]byte, size)
	if _, err := rand.Read(p); err != nil {
		panic(err)
	}
	return p
}
