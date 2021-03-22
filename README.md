# bitw

A simple BitWarden client. Requires Go 1.15 or later.

	cd $(mktemp -d); go mod init tmp; go get mvdan.cc/bitw

The goal is a static and portable client which integrates well with one's
system. For example, on Linux it implements the `org.freedesktop.secrets` D-Bus
service.

Note that this tool is still a work in progress.

#### Quickstart

Log in and sync, providing a password when asked:

	export EMAIL=you@domain.com
	bitw sync

You can then view your secrets:

	bitw dump

You can also start the D-Bus service, and use it:

	bitw serve
	secret-tool lookup name mysecret

#### Non-goals

These features are not planned at the moment:

* A graphical interface - use `vault.bitwarden.com`
* Querying secrets directly - use D-Bus clients like `secret-tool`
* Integration with gnome-keyring - they both implement the same D-Bus service

#### Further reading

Talking to BitWarden:

* https://github.com/jcs/rubywarden/blob/master/API.md
* https://fossil.birl.ca/doc/trunk/docs/build/html/crypto.html

Integrating with the OS:

* https://specifications.freedesktop.org/secret-service/
* https://www.chucknemeth.com/linux/security/keyring/secret-tool
