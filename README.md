## WhatsApp c library

A fast and lightweight c library to connect to WhatsApp. Requires an always
connected phone capable of login into the web client.

Uses the following libraries:

- libwebsockets
- libqrencode
- libcrypto
- libjson-c
- libprotobuf-c

Still under HEAVY development. Pull requests are appreciated.

Based on the great reverse engineering work of sigalor:
[whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng)

### Objective

The library will provide a simple way to build clients. For instance a bitlbee
plugin to add WhatsApp as an available protocol to IRC.

### Current status

By now it can only connect to the WhatsApp websocket server, login using the QR
and start receiving messages. The encrypted messages are succesfully decrypted.

	F8 04 09 0A 4B F8 01 F8  02 34 FC 5B 0A 40 0A 1A   ....K....4.[.@..
	33 34 36 36 36 36 36 36  36 36 36 40 73 2E 77 68   34666666666@s.wh
	61 74 73 61 70 70 2E 6E  65 74 10 01 1A 20 42 42   atsapp.net... BB
	30 30 30 30 30 30 30 30  30 30 30 30 30 30 30 30   0000000000000000
	30 30 30 30 30 30 30 30  30 30 30 30 30 30 12 0F   00000000000000..
	0A 0D 54 65 73 74 69 6E  67 20 6C 69 62 77 61 18   ..Testing libwa.
	A8 85 E7 DE 05 20 00                               ..... ..........

Received and sent text messages are displayed:

	346XXXXXXXX@s.whatsapp.net: Have you ever seen a supernova?
	346XXXXXXXX@s.whatsapp.net: Well...
	346XXXXXXXX@s.whatsapp.net: Sometimes I power my phone screen in the dark
	346XXXXXXXX@s.whatsapp.net: At maximum brightness

