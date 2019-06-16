# bitw

A simple BitWarden client.

	cd $(mktemp -d); go mod init tmp; go get mvdan.cc/bitw

The goal is a static and portable client which integrates well with one's
system. For example, on Linux it will implement the `org.freedesktop.secrets`
D-Bus service.

Note that this tool is still a work in progress.

#### Further reading

Talking to BitWarden:

* https://github.com/jcs/rubywarden/blob/master/API.md
* https://fossil.birl.ca/bitwarden-cli/doc/trunk/docs/build/html/crypto.html

Integrating with the OS:

* https://freedesktop.org/wiki/Specifications/secret-storage-spec/secrets-api-0.1.html
