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
}

type CipherString struct {
	Type CipherStringType

	IV, CT, MAC []byte
}

type CipherStringType int

// Taken from https://github.com/bitwarden/jslib/blob/f30d6f8027055507abfdefd1eeb5d9aab25cc601/src/enums/encryptionType.ts
const (
	AesCbc256_B64                     CipherStringType = 0
	AesCbc128_HmacSha256_B64          CipherStringType = 1
	AesCbc256_HmacSha256_B64          CipherStringType = 2
	Rsa2048_OaepSha256_B64            CipherStringType = 3
	Rsa2048_OaepSha1_B64              CipherStringType = 4
	Rsa2048_OaepSha256_HmacSha256_B64 CipherStringType = 5
	Rsa2048_OaepSha1_HmacSha256_B64   CipherStringType = 6
)

func (t CipherStringType) HasMAC() bool {
	return t != AesCbc256_B64
}

func (s CipherString) IsZero() bool {
	return s.Type == 0 && s.IV == nil && s.CT == nil && s.MAC == nil
}

func (s CipherString) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s CipherString) String() string {
	if s.IsZero() {
		return ""
	}
	if !s.Type.HasMAC() {
		return fmt.Sprintf("%d.%s|%s",
			s.Type,
			b64enc.EncodeToString(s.IV),
			b64enc.EncodeToString(s.CT),
		)
	}
	return fmt.Sprintf("%d.%s|%s|%s",
		s.Type,
		b64enc.EncodeToString(s.IV),
		b64enc.EncodeToString(s.CT),
		b64enc.EncodeToString(s.MAC),
	)
}

func (s *CipherString) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	i := bytes.IndexByte(data, '.')
	if i < 0 {
		return fmt.Errorf("cipher string does not contain a type: %q", data)
	}
	typStr := string(data[:i])
	var err error
	if t, err := strconv.Atoi(typStr); err != nil {
		return fmt.Errorf("invalid cipher string type: %q", typStr)
	} else {
		s.Type = CipherStringType(t)
	}
	switch s.Type {
	case AesCbc128_HmacSha256_B64, AesCbc256_HmacSha256_B64, AesCbc256_B64:
	default:
		return fmt.Errorf("unsupported cipher string type: %d", s.Type)
	}

	data = data[i+1:]
	parts := bytes.Split(data, []byte("|"))
	wantParts := 3
	if !s.Type.HasMAC() {
		wantParts = 2
	}
	if len(parts) != wantParts {
		return fmt.Errorf("cipher string type requires %d parts: %q", wantParts, data)
	}

	// TODO: do a single []byte allocation for all fields
	if s.IV, err = b64decode(parts[0]); err != nil {
		return err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return err
	}
	if s.Type.HasMAC() {
		if s.MAC, err = b64decode(parts[2]); err != nil {
			return err
		}
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

type Cipher struct {
	Type         CipherType
	ID           uuid.UUID
	Name         CipherString
	Edit         bool
	RevisionDate time.Time

	// The rest of the fields are optional. Omit from the JSON if empty.

	FolderID            *uuid.UUID  `json:",omitempty"`
	OrganizationID      *uuid.UUID  `json:",omitempty"`
	Favorite            bool        `json:",omitempty"`
	Attachments         interface{} `json:",omitempty"`
	OrganizationUseTotp bool        `json:",omitempty"`
	CollectionIDs       []string    `json:",omitempty"`
	Fields              []Field     `json:",omitempty"`

	Card       *Card         `json:",omitempty"`
	Identity   *Identity     `json:",omitempty"`
	Login      *Login        `json:",omitempty"`
	Notes      *CipherString `json:",omitempty"`
	SecureNote *SecureNote   `json:",omitempty"`
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
		got, err = secrets.decryptStr(c.Name)
	case "username":
		got, err = secrets.decryptStr(c.Login.Username)
	default:
		return false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt %s: %v\n", attr, err)
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
	URI      CipherString
	URIs     []URI
	Username CipherString `json:",omitempty"`
	Totp     string       `json:",omitempty"`
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
	if err := jsonGET(ctx, apiURL+"/sync", &globalData.Sync); err != nil {
		return fmt.Errorf("could not sync: %v", err)
	}
	globalData.LastSync = now
	saveData = true
	return nil
}
