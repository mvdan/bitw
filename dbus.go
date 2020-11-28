// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path"

	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
)

const (
	dbusName  = "org.freedesktop.secrets"
	objPrefix = "/org/freedesktop/secrets"
)

var (
	// From 'man sd-bus-errors'.
	errNotSupported = dbus.NewError("org.freedesktop.DBus.Error.NotSupported", nil)
	errInvalidArgs  = dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", nil)

	errNoSuchObject = dbus.NewError("org.freedesktop.Secret.Error.NoSuchObject", nil)
	errAlreadyTaken = fmt.Errorf("dbus name %s already taken", dbusName)
)

func dbusErrorf(format string, args ...interface{}) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{
		fmt.Sprintf(format, args...),
	})
}

func objPath(suffix string) dbus.ObjectPath {
	return dbus.ObjectPath(objPrefix + suffix)
}

func serveDBus(ctx context.Context) error {
	conn, err := dbus.SessionBusPrivate(
	// TODO: expose this via a serve flag
	// dbus.WithIncomingInterceptor(func(msg *dbus.Message) {
	// 	fmt.Println("in:", msg)
	// }),
	// dbus.WithOutgoingInterceptor(func(msg *dbus.Message) {
	// 	fmt.Println("out:", msg)
	// }),
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Auth(nil); err != nil {
		return err
	}
	if err := conn.Hello(); err != nil {
		return err
	}

	srv := &dbusService{}
	conn.ExportSubtree(srv, objPrefix, "org.freedesktop.Secret.Service")
	conn.ExportSubtree(srv, objPrefix, "org.freedesktop.Secret.Item")
	conn.ExportSubtree(srv, objPrefix, "org.freedesktop.DBus.Properties")

	reply, err := conn.RequestName(dbusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errAlreadyTaken
	}

	fmt.Fprintf(os.Stderr, "Listening on %s\n", dbusName)
	<-ctx.Done()
	conn.Close()
	return ctx.Err()
}

type dbusService struct {
	aesKey []byte
}

func (d *dbusService) OpenSession(algo string, input dbus.Variant) (output dbus.Variant, result dbus.ObjectPath, _ *dbus.Error) {
	// TODO: support multiple sessions at once
	session := objPath("/session/default")

	switch algo {
	case "plain":
		return dbus.MakeVariant(""), session, nil
	case "dh-ietf1024-sha256-aes128-cbc-pkcs7":
		group := rfc2409SecondOakleyGroup()
		private, public, err := group.NewKeypair()
		if err != nil {
			return output, "/", dbusErrorf("%s", err)
		}
		output = dbus.MakeVariant(public.Bytes()) // math/big.Int.Bytes is big endian

		inputBytes, ok := input.Value().([]byte)
		if !ok {
			return output, "/", errInvalidArgs
		}
		theirPublic := new(big.Int)
		theirPublic.SetBytes(inputBytes)
		d.aesKey, err = group.keygenHKDFSHA256AES128(theirPublic, private)
		if err != nil {
			return output, "/", dbusErrorf("%s", err)
		}
		return output, session, nil
	default:
		return output, "/", errNotSupported
	}
}

func (d *dbusService) SearchItems(attributes map[string]string) (unlocked, locked []dbus.ObjectPath, _ *dbus.Error) {
Ciphers:
	for _, cipher := range globalData.Sync.Ciphers {
		for attr, value := range attributes {
			if !cipher.Match(attr, value) {
				continue Ciphers
			}
		}
		// Object paths can only contain letters, numbers, and underscores.
		id := rawUUID(cipher.ID)
		unlocked = append(unlocked, objPath("/collections/default/"+id))
	}
	return
}

func (d *dbusService) cipherByPath(item dbus.ObjectPath) (Cipher, bool) {
	id := path.Base(string(item))
	for _, cipher := range globalData.Sync.Ciphers {
		if rawUUID(cipher.ID) == id {
			return cipher, true
		}
	}
	return Cipher{}, false
}

func (d *dbusService) secretByPath(item, session dbus.ObjectPath) (secret dbusSecret, _ *dbus.Error) {
	secret.Session = session

	cipher, ok := d.cipherByPath(item)
	if !ok {
		return secret, errNoSuchObject
	}

	password, err := secrets.decrypt(cipher.Login.Password)
	if err != nil {
		return secret, dbusErrorf("%s", err)
	}
	secret.ContentType = "text/plain"
	if d.aesKey == nil {
		secret.Value = password
		return secret, nil
	}
	iv, ciphertext, err := unauthenticatedAESCBCEncrypt(password, d.aesKey)
	if err != nil {
		return secret, dbusErrorf("%s", err)
	}
	secret.Parameters = iv
	secret.Value = ciphertext
	return secret, nil
}

func rawUUID(id uuid.UUID) string {
	return hex.EncodeToString(id[:])
}

type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func (d *dbusService) GetAll(msg dbus.Message, iface string) (map[string]dbus.Variant, *dbus.Error) {
	props := make(map[string]dbus.Variant)
	item := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	switch iface {
	case "org.freedesktop.Secret.Item":
		props["Locked"] = dbus.MakeVariant(false)
		props["Attributes"] = dbus.MakeVariant(map[string]string{
			// Old secret-tool versions may panic if this attribute
			// is left out.
			"xdg:schema": "",
		})
		cipher, ok := d.cipherByPath(item)
		if !ok {
			return nil, errNoSuchObject
		}
		props["Created"] = dbus.MakeVariant(uint64(cipher.RevisionDate.Unix()))
		props["Modified"] = dbus.MakeVariant(uint64(cipher.RevisionDate.Unix()))
	// case "org.freedesktop.Secret.Collection":
	// case "org.freedesktop.Secret.Service":
	default:
		return nil, errNotSupported
	}
	return props, nil
}

func (d *dbusService) GetSecret(msg dbus.Message, session dbus.ObjectPath) (secret dbusSecret, _ *dbus.Error) {
	item := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	return d.secretByPath(item, session)
}

func (d *dbusService) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (byPath map[dbus.ObjectPath]dbusSecret, _ *dbus.Error) {
	byPath = make(map[dbus.ObjectPath]dbusSecret)
	for _, item := range items {
		secret, err := d.secretByPath(item, session)
		if err != nil {
			return nil, err
		}
		byPath[item] = secret
	}
	return
}
