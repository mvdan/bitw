// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"
	"time"
)

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers []Cipher
	Domains Domains
}

type Profile struct {
	ID                 string
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint string
	Culture            string
	TwoFactorEnabled   bool
	Key                string
	PrivateKey         string
	SecurityStamp      string
	Organizations      []string
}

type Folder struct {
	ID           string
	Name         string
	RevisionDate time.Time
}

type Domains struct {
	EquivalentDomains       []string
	GlobalEquivalentDomains []GlobalEquivalentDomains
}

type GlobalEquivalentDomains struct {
	Type     int
	Domains  []string
	Excluded bool
}

type Cipher struct {
	Type                int
	FolderID            string
	OrganizationID      string
	Favorite            bool
	Edit                bool
	ID                  string
	Attachments         []string
	OrganizationUseTotp bool
	RevisionDate        time.Time
	CollectionIDs       []string

	Card       string
	Fields     []string
	Identity   string
	Login      Login
	Name       string
	Notes      string
	SecureNote SecureNote
}

type Login struct {
	Password string
	Totp     string
	URI      string
	URIs     []URI
	Username string
}

type URI struct {
	URI   string
	Match int
}

type SecureNote struct {
	Type int
}

func sync(ctx context.Context) error {
	now := time.Now().UTC()
	if err := jsonGET(ctx, apiURL+"/sync", &data.Sync); err != nil {
		return fmt.Errorf("could not sync: %v", err)
	}
	data.LastSync = now
	saveData = true
	return nil
}
