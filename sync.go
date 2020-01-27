// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers []Cipher
	Domains Domains
}

type CipherString struct {
	Type int

	IV, CT, MAC []byte
}

func (s CipherString) MarshalText() ([]byte, error) {
	if s.Type == 0 {
		return nil, nil
	}
	return []byte(fmt.Sprintf("%d.%s|%s|%s",
		s.Type,
		b64enc.EncodeToString(s.IV),
		b64enc.EncodeToString(s.CT),
		b64enc.EncodeToString(s.MAC),
	)), nil
}

func (s *CipherString) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	i := bytes.IndexByte(data, '.')
	if i < 0 {
		return fmt.Errorf("invalid cipher string %q", data)
	}
	typStr := string(data[:i])
	var err error
	if s.Type, err = strconv.Atoi(typStr); err != nil {
		return fmt.Errorf("invalid cipher type %q", typStr)
	}
	data = data[i+1:]

	parts := bytes.Split(data, []byte("|"))
	if len(parts) != 3 {
		return fmt.Errorf("invalid cipher string %q", data)
	}
	// TODO: do a single []byte allocation for all three
	if s.IV, err = b64decode(parts[0]); err != nil {
		return err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return err
	}
	if s.MAC, err = b64decode(parts[2]); err != nil {
		return err
	}
	return nil
}

func b64decode(src []byte) ([]byte, error) {
	dst := make([]byte, b64enc.DecodedLen(len(src)))
	n, err := b64enc.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	dst = dst[:n]
	return dst, nil
}

type Organization struct {
	Object          string
	Id              uuid.UUID
	Name            string
	UseGroups       bool
	UseDirectory    bool
	UseEvents       bool
	UseTotp         bool
	Use2fa          bool
	UseApi          bool
	UsersGetPremium bool
	SelfHost        bool
	Seats           int
	MaxCollections  int
	MaxStorageGb    int
	Key             string
	Status          int
	Type            int
	Enabled         bool
}

type Profile struct {
	ID                 uuid.UUID
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
	Organizations      []Organization
}

type Folder struct {
	ID           uuid.UUID
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
	Type                CipherType
	FolderID            uuid.UUID
	OrganizationID      uuid.UUID
	Favorite            bool
	Edit                bool
	ID                  uuid.UUID
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

type CipherType int

const (
	_ CipherType = iota
	CipherLogin
	CipherCard
	CipherIdentity
	CipherNote
)

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
		got = c.ID.String()
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
	Type  FieldType
	Name  CipherString
	Value CipherString
}

type FieldType int

type Login struct {
	Password CipherString
	Totp     string
	URI      CipherString
	URIs     []URI
	Username CipherString
}

type URI struct {
	URI   string
	Match URIMatch
}

type URIMatch int

type SecureNote struct {
	Type SecureNoteType
}

type SecureNoteType int

func sync(ctx context.Context) error {
	now := time.Now().UTC()
	if err := jsonGET(ctx, apiURL+"/sync", &data.Sync); err != nil {
		return fmt.Errorf("could not sync: %v", err)
	}
	data.LastSync = now
	saveData = true
	return nil
}
