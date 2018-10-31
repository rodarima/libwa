## Key computation from the secret

The client is required to generate a random private key, using X25519. For
testing purposes, a fixed key will be used here instead.

	Private key:
	20 6A FD 2E D1 88 21 2B  17 E8 2A FE 81 CF 06 0B
	4C D4 1A 8A 5B F0 19 D9  15 76 C1 5A 90 D9 52 5B

	Public key:
	56 EE B4 93 8E CE 19 FE  42 8F 6E C5 A5 E8 CF C1
	93 A3 8F 7F 62 85 FE C3  93 AE 56 A6 4D 64 AC 5E

We refer to this keypair as the client key. After the login procedure, a "conn"
message should arrive. The secret returned by the server in the message contains
base64 data.

	"secret":"1hJSpAGh2E7hPcy1WknGrbMo4y38fJ7ABjv7hwl773
	LWqge2pg+wmbqu8Grn48YxWgfcNpesfFKO/HSHPPpeBS0UWXsorc
	6NexVozC/9/qOnX8PDDZh6Ma/f+eL9Sju13C87Lxk4K8b8/Gt6B9
	3ns5nViSCgPg42JKAKaf3cwzXM+D/zA91VDnnPfmu7epat"

After decoding the base64, we get 144 bytes of data:

	Secret:
	D6 12 52 A4 01 A1 D8 4E  E1 3D CC B5 5A 49 C6 AD } ---> peer public key
	B3 28 E3 2D FC 7C 9E C0  06 3B FB 87 09 7B EF 72 }
	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05
	2D 14 59 7B 28 AD CE 8D  7B 15 68 CC 2F FD FE A3
	A7 5F C3 C3 0D 98 7A 31  AF DF F9 E2 FD 4A 3B B5
	DC 2F 3B 2F 19 38 2B C6  FC FC 6B 7A 07 DD E7 B3
	99 D5 89 20 A0 3E 0E 36  24 A0 0A 69 FD DC C3 35
	CC F8 3F F3 03 DD 55 0E  79 CF 7E 6B BB 7A 96 AD

From the first 32 bytes, the peer public key is extracted.

	Peer public key:
	D6 12 52 A4 01 A1 D8 4E  E1 3D CC B5 5A 49 C6 AD
	B3 28 E3 2D FC 7C 9E C0  06 3B FB 87 09 7B EF 72

With the client key and the peer public key, we can derive a shared key, using
X25519, which is also 32 bytes long.

	Shared key:
	F8 5B 64 7F EC 3D 1E BA  F9 D7 3B 2F B7 C4 4B C1
	29 CA FB FB EC A9 27 2D  E7 FD 8E 99 4F BD 93 65

This key must be expanded up to 80 bytes, using the key derivation function HKDF
with the hash function SHA256.

	Expanded key:
	AA D4 CF 74 11 A9 96 BC  58 78 95 23 75 EF C3 17
	86 9C F4 6B 77 AF C5 07  82 4E 7D A6 8A 99 91 25
	34 4E C9 E0 BD 77 9F 10  71 9E AF 64 B2 AF 2E 3E
	5E 15 2C 0A FA 52 39 56  6B EE F7 C3 55 E0 39 9E
	1D D5 03 4A 8A 68 B3 79  A1 26 CC 82 A8 89 D5 EE

### Verification


We can verify that the secret is correct, and that the extracted key matches,
and thus, all previous steps were correct, by using the authentication code
HMAC. The key will be 32 bytes long, from the expanded key, in the interval
[32,64].

	Expanded key:
	AA D4 CF 74 11 A9 96 BC  58 78 95 23 75 EF C3 17
	86 9C F4 6B 77 AF C5 07  82 4E 7D A6 8A 99 91 25
	34 4E C9 E0 BD 77 9F 10  71 9E AF 64 B2 AF 2E 3E } ---> HMAC key
	5E 15 2C 0A FA 52 39 56  6B EE F7 C3 55 E0 39 9E }
	1D D5 03 4A 8A 68 B3 79  A1 26 CC 82 A8 89 D5 EE

	HMAC key
	34 4E C9 E0 BD 77 9F 10  71 9E AF 64 B2 AF 2E 3E
	5E 15 2C 0A FA 52 39 56  6B EE F7 C3 55 E0 39 9E

From the secret, we obtain the HMAC sum that should match with the computed
value. It is extracted from the interval [32,64] of the secret.

	Secret:
	D6 12 52 A4 01 A1 D8 4E  E1 3D CC B5 5A 49 C6 AD
	B3 28 E3 2D FC 7C 9E C0  06 3B FB 87 09 7B EF 72
	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31 } ---> HMAC sum
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05 }
	2D 14 59 7B 28 AD CE 8D  7B 15 68 CC 2F FD FE A3
	A7 5F C3 C3 0D 98 7A 31  AF DF F9 E2 FD 4A 3B B5
	DC 2F 3B 2F 19 38 2B C6  FC FC 6B 7A 07 DD E7 B3
	99 D5 89 20 A0 3E 0E 36  24 A0 0A 69 FD DC C3 35
	CC F8 3F F3 03 DD 55 0E  79 CF 7E 6B BB 7A 96 AD

	HMAC sum
	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05

The content which will be verified is the rest of the secret, placed
contiguously, that is the part of [0,32] and [64,80]. In total 112 bytes long.

	Content to be verified
	D6 12 52 A4 01 A1 D8 4E  E1 3D CC B5 5A 49 C6 AD
	B3 28 E3 2D FC 7C 9E C0  06 3B FB 87 09 7B EF 72
	2D 14 59 7B 28 AD CE 8D  7B 15 68 CC 2F FD FE A3
	A7 5F C3 C3 0D 98 7A 31  AF DF F9 E2 FD 4A 3B B5
	DC 2F 3B 2F 19 38 2B C6  FC FC 6B 7A 07 DD E7 B3
	99 D5 89 20 A0 3E 0E 36  24 A0 0A 69 FD DC C3 35
	CC F8 3F F3 03 DD 55 0E  79 CF 7E 6B BB 7A 96 AD

After the verification, we should compare that the computed HMAC sum is exactly
the same as the HMAC sum extracted before.

	Computed HMAC sum:
	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05

	Expected HMAC sum:
	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05

## Decryption of the keys

There are 2 keys that we will use to decrypt all encrypted messages. The two
keys are called enc-key and mac-key.

In order to extract them, we need to decrypt the expanded key, using AES256 with
the CBC mode.

The AES key will be 32 bytes long, and is extracted from the first 32 bytes of
the expanded key:

	Expanded key:
	AA D4 CF 74 11 A9 96 BC  58 78 95 23 75 EF C3 17 } ---> AES key
	86 9C F4 6B 77 AF C5 07  82 4E 7D A6 8A 99 91 25 }
	34 4E C9 E0 BD 77 9F 10  71 9E AF 64 B2 AF 2E 3E
	5E 15 2C 0A FA 52 39 56  6B EE F7 C3 55 E0 39 9E
	1D D5 03 4A 8A 68 B3 79  A1 26 CC 82 A8 89 D5 EE

	key:
	AA D4 CF 74 11 A9 96 BC  58 78 95 23 75 EF C3 17
	86 9C F4 6B 77 AF C5 07  82 4E 7D A6 8A 99 91 25

The initialization vector (iv) will be 16 bytes long, and is the last 16 bytes
of the expanded key:

	Expanded key:
	AA D4 CF 74 11 A9 96 BC  58 78 95 23 75 EF C3 17 } ---> AES key
	86 9C F4 6B 77 AF C5 07  82 4E 7D A6 8A 99 91 25 }
	34 4E C9 E0 BD 77 9F 10  71 9E AF 64 B2 AF 2E 3E
	5E 15 2C 0A FA 52 39 56  6B EE F7 C3 55 E0 39 9E
	1D D5 03 4A 8A 68 B3 79  A1 26 CC 82 A8 89 D5 EE } ---> AES iv

	iv:
	1D D5 03 4A 8A 68 B3 79  A1 26 CC 82 A8 89 D5 EE

And the content to be decrypted, is the secret in the interval [64,144], which
is 80 bytes long.

	Secret:
	D6 12 52 A4 01 A1 D8 4E  E1 3D CC B5 5A 49 C6 AD
	B3 28 E3 2D FC 7C 9E C0  06 3B FB 87 09 7B EF 72
	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05
	2D 14 59 7B 28 AD CE 8D  7B 15 68 CC 2F FD FE A3 } ---> encrypted data
	A7 5F C3 C3 0D 98 7A 31  AF DF F9 E2 FD 4A 3B B5 }
	DC 2F 3B 2F 19 38 2B C6  FC FC 6B 7A 07 DD E7 B3 }
	99 D5 89 20 A0 3E 0E 36  24 A0 0A 69 FD DC C3 35 }
	CC F8 3F F3 03 DD 55 0E  79 CF 7E 6B BB 7A 96 AD }

	encrypted data:
	2D 14 59 7B 28 AD CE 8D  7B 15 68 CC 2F FD FE A3
	A7 5F C3 C3 0D 98 7A 31  AF DF F9 E2 FD 4A 3B B5
	DC 2F 3B 2F 19 38 2B C6  FC FC 6B 7A 07 DD E7 B3
	99 D5 89 20 A0 3E 0E 36  24 A0 0A 69 FD DC C3 35
	CC F8 3F F3 03 DD 55 0E  79 CF 7E 6B BB 7A 96 AD

After the decryption, the 64 bytes result should be splited in two parts of 32
bytes, which will form the two keys. The first 32 bytes is the enc-key, the
second 32 bytes, the mac-key.

	Decrypted keys:
	11 D7 9B 9D 3C E3 CA CB  34 69 77 05 E2 34 F8 64 } ---> enc-key
	8C DF 02 0C 21 77 26 4B  4A 1D 1D B1 3E B1 DD 0E }
	C1 63 AC 31 55 6B 76 20  F6 22 70 C6 F1 39 27 42 } ---> mac-key
	2F 22 8B F3 3D 38 61 C9  01 89 3D 32 F8 49 F3 E1 }

	enc-key:
	11 D7 9B 9D 3C E3 CA CB  34 69 77 05 E2 34 F8 64
	8C DF 02 0C 21 77 26 4B  4A 1D 1D B1 3E B1 DD 0E

	mac-key:
	C1 63 AC 31 55 6B 76 20  F6 22 70 C6 F1 39 27 42
	2F 22 8B F3 3D 38 61 C9  01 89 3D 32 F8 49 F3 E1

The enc-key and mac-key must be saved for later use.

### Summary

The contents of each part can be summarized here:

	Secret:
	D6 12 52 A4 01 A1 D8 4E  E1 3D CC B5 5A 49 C6 AD } ---> peer public key
	B3 28 E3 2D FC 7C 9E C0  06 3B FB 87 09 7B EF 72 }

	D6 AA 07 B6 A6 0F B0 99  BA AE F0 6A E7 E3 C6 31 } ---> HMAC sum
	5A 07 DC 36 97 AC 7C 52  8E FC 74 87 3C FA 5E 05 }

	2D 14 59 7B 28 AD CE 8D  7B 15 68 CC 2F FD FE A3 } ---> encrypted data
	A7 5F C3 C3 0D 98 7A 31  AF DF F9 E2 FD 4A 3B B5 }
	DC 2F 3B 2F 19 38 2B C6  FC FC 6B 7A 07 DD E7 B3 }
	99 D5 89 20 A0 3E 0E 36  24 A0 0A 69 FD DC C3 35 }
	CC F8 3F F3 03 DD 55 0E  79 CF 7E 6B BB 7A 96 AD }


	Expanded key:
	AA D4 CF 74 11 A9 96 BC  58 78 95 23 75 EF C3 17 } ---> AES key
	86 9C F4 6B 77 AF C5 07  82 4E 7D A6 8A 99 91 25 }

	34 4E C9 E0 BD 77 9F 10  71 9E AF 64 B2 AF 2E 3E } ---> HMAC key
	5E 15 2C 0A FA 52 39 56  6B EE F7 C3 55 E0 39 9E }

	1D D5 03 4A 8A 68 B3 79  A1 26 CC 82 A8 89 D5 EE } ---> AES iv

