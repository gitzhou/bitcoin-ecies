# Bitcoin ECIES

**Encrypt message with bitcoin public key, and decrypt with the corresponding private key**

[Electrum](https://github.com/spesmilo/electrum) and [Electron Cash](https://github.com/Electron-Cash/Electron-Cash) have an implementation under `Tools --> Encrypt/decrypt message`

![Imgur](https://i.imgur.com/nshs7qQ.png)

This is a GoLang version of the feature, compatible with Electrum/Electron Cash

Node.js version please refer to [monkeylord/electrum-ecies](https://github.com/monkeylord/electrum-ecies)

# Usage

```
$ go get github.com/gitzhou/bitcoin-ecies
```

Below is a demo, or check the unit test code for an example

```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/gitzhou/bitcoin-ecies"
)

func main() {
	// Public key compressed
	publicKey, _ := hex.DecodeString("04866269bf6c2d71968ec46797b91b207affeea74dbba1f181ff354abbfbdfe9327c58d1c0681e328f555f5aa6ec2e7543baf2b3f89ce90720d617da710ce1ea93")
	// Private key Wallet Import Format(WIF): 5KdBypVKceVrUNbWmxDJALGJ9fo9rwNYTjppps8gQb9C8VHUXzr
	// Transfer to HEX with https://gobittest.appspot.com/PrivateKey
	privateKey, _ := hex.DecodeString("ee3231b5deea48b619814d72a6e1aa04a9f521df281afad5ada89f5393941b1c")

	message := "hello world"
	encrypted, err := bitcoin_ecies.EncryptMessage(message, publicKey)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(encrypted)
	plain, err := bitcoin_ecies.DecryptMessage(encrypted, privateKey)
	if err != nil {
		fmt.Println(err.Error())
	}
	if message != plain {
		fmt.Println("data mismatch after encrypt and decrypt")
	}
}
```

# Reference

- [bitcoin.py](https://github.com/Electron-Cash/Electron-Cash/blob/master/lib/bitcoin.py#L645)
- [golang实现ECC加密](https://lvbay.github.io/2018/05/13/golang%E5%AE%9E%E7%8E%B0ECC%E5%8A%A0%E5%AF%86/)
- [package secp256k1](https://godoc.org/github.com/decred/dcrd/dcrec/secp256k1)
- [ECIES ( Elliptic Curve Integrated Encryption Scheme )](https://github.com/EasonWang01/Introduction-to-cryptography/blob/master/3.6%20ECIES.md)

# Donation

Appreciated and THANK YOU :smile:

You can donate **Bitcoin**, **Bitcoin Cash** or **Bitcoin SV** to `13L81fdKqdif6AEFAfBymXdyB3hDvBvdp9` to buy me a cup of coffee :coffee:

![Imgur](https://i.imgur.com/oowYIk6.png)

# License

MIT
