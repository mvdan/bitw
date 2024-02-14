# bitw

A simple BitWarden client. Requires Go 1.19 or later.

	go install mvdan.cc/bitw@latest

The goal is a static and portable client which integrates well with one's
system. For example, on Linux it implements the `org.freedesktop.secrets` D-Bus
service.

**Note that this project isn't being actively developed right now, as I lack the time.**
I am happy to hand over the repository to whoever can maintain and develop the project,
with the only requirement that they make at least two non-trivial contributions first.
Other projects with similar goals like https://github.com/quexten/goldwarden might be interesting too,
which tackles desktop Bitwarden integration in Go via a GUI and autotype rather than a D-Bus service.

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
* Desktop autotype/autofill integration - it could be built on top of D-Bus secrets

#### Further reading

Talking to BitWarden:

* https://github.com/jcs/rubywarden/blob/master/API.md
* https://fossil.birl.ca/doc/trunk/docs/build/html/crypto.html

Integrating with the OS:

* https://specifications.freedesktop.org/secret-service/
* https://www.chucknemeth.com/linux/security/keyring/secret-tool
