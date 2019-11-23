// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers []Cipher
	Domains Domains
}

type CipherString string

type Profile struct {
	ID                 string
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint string
	Culture            string
	TwoFactorEnabled   bool
	Key                CipherString
	PrivateKey         CipherString
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
	Attachments         interface{} // TODO
	OrganizationUseTotp bool
	RevisionDate        time.Time
	CollectionIDs       []string

	Card       Card
	Fields     []Field
	Identity   Identity
	Login      Login
	Name       CipherString
	Notes      CipherString
	SecureNote SecureNote
}

type Card struct {
	CardholderName CipherString
	Brand          CipherString
	Number         CipherString
	ExpMonth       CipherString
	ExpYear        CipherString
	Code           CipherString
}

type Identity struct {
	Title      CipherString
	FirstName  CipherString
	MiddleName CipherString
	LastName   CipherString

	Username       CipherString
	Company        CipherString
	SSN            CipherString
	PassportNumber CipherString
	LicenseNumber  CipherString

	Email      CipherString
	Phone      CipherString
	Address1   CipherString
	Address2   CipherString
	Address3   CipherString
	City       CipherString
	State      CipherString
	PostalCode CipherString
	Country    CipherString
}

func (c *Cipher) Match(attr, value string) bool {
	got := ""
	var err error
	switch attr {
	case "id":
		got = c.ID
	case "name":
		got, err = decryptStr(c.Name)
	case "username":
		got, err = decryptStr(c.Login.Username)
	default:
		return false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt %s: %v", attr, err)
		return false
	}
	return got == value
}

type Field struct {
	Type  int
	Name  string
	Value string
}

type Login struct {
	Password CipherString
	Totp     string
	URI      CipherString
	URIs     []URI
	Username CipherString
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
