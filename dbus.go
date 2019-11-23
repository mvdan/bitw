// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"path"

	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
)

const (
	dbusName  = "org.freedesktop.secrets"
	objPrefix = "/org/freedesktop/secrets"
)

var (
	errNotSupported = dbus.NewError("org.freedesktop.DBus.Error.NotSupported", nil)
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

	fmt.Printf("Listening on %s\n", dbusName)
	<-ctx.Done()
	conn.Close()
	return ctx.Err()
}

type dbusService struct{}

func (d *dbusService) OpenSession(algo string, input dbus.Variant) (output dbus.Variant, result dbus.ObjectPath, _ *dbus.Error) {
	switch algo {
	case "plain":
		return dbus.MakeVariant(""), objPath("/session/default"), nil
	default:
		// TODO: support dh-ietf1024-sha256-aes128-cbc-pkcs7?
		return output, "/", errNotSupported
	}
}

func (d *dbusService) SearchItems(attributes map[string]string) (unlocked, locked []dbus.ObjectPath, _ *dbus.Error) {
Ciphers:
	for _, cipher := range data.Sync.Ciphers {
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

func (d *dbusService) secretByPath(item dbus.ObjectPath) (Cipher, bool) {
	id := path.Base(string(item))
	for _, cipher := range data.Sync.Ciphers {
		if rawUUID(cipher.ID) == id {
			return cipher, true
		}
	}
	return Cipher{}, false
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
		cipher, ok := d.secretByPath(item)
		if !ok {
			return nil, errNoSuchObject
		}
		name, err := decryptStr(cipher.Name)
		if err != nil {
			return nil, dbusErrorf("%s", err)
		}
		props["Label"] = dbus.MakeVariant(name)
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
	cipher, ok := d.secretByPath(item)
	if !ok {
		return secret, errNoSuchObject
	}
	password, err := decrypt(cipher.Login.Password)
	if err != nil {
		return secret, dbusErrorf("%s", err)
	}
	return dbusSecret{
		Session:     session,
		Value:       password,
		ContentType: "text/plain",
	}, nil
}

func (d *dbusService) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (secrets map[dbus.ObjectPath]dbusSecret, _ *dbus.Error) {
	secrets = make(map[dbus.ObjectPath]dbusSecret)
	for _, item := range items {
		cipher, ok := d.secretByPath(item)
		if !ok {
			return nil, errNoSuchObject
		}
		password, err := decrypt(cipher.Login.Password)
		if err != nil {
			return nil, dbusErrorf("%s", err)
		}
		secrets[item] = dbusSecret{
			Session:     session,
			Value:       password,
			ContentType: "text/plain",
		}
	}
	return
}
