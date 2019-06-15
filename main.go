// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// TODO: move these to a config file
var (
	apiURL = "https://api.bitwarden.com"

	email    = os.Getenv("EMAIL")
	password = os.Getenv("PASSWORD")
)

func run() error {
	ctx := context.Background()

	var prelog preLoginResponse
	if err := jsonPOST(ctx, "/accounts/prelogin", &prelog, preLogin{
		Email: email,
	}); err != nil {
		return err
	}
	fmt.Printf("%#v\n", prelog)

	return nil
}
