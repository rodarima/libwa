## WhatsApp c library

A fast and lightweight c library to connect to WhatsApp. Requires an always
connected phone capable of login into the web client.

Uses the following libraries:

- libwebsockets
- libqrencode
- libcrypto
- libjson-c

Still under HEAVY development. Pull requests are appreciated.

Based on the great reverse engineering work of sigalor:
[whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng)

### Objective

The library will provide a simple way to build clients. For instance a bitlbee
plugin to add WhatsApp as an available protocol to IRC.
