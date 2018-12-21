package bitcoin_ecies

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var data = "hello world"
var blockSize = 16

func TestPaddingData(t *testing.T) {
	padding := AppendPKCS7Padding([]byte(data), blockSize)
	if len(padding) != blockSize {
		t.Errorf("append padding length error")
	}
	for _, v := range padding[len(padding):] {
		if int(v) != blockSize-len(data) {
			t.Errorf("append padding content error")
		}
	}
	stripedPadding, err := StripPKCS7Padding(padding, blockSize)
	if err != nil {
		t.Errorf(err.Error())
	}
	if string(stripedPadding[:]) != data {
		t.Errorf("data mismatch after append and strip padding")
	}
}

var iv, _ = hex.DecodeString("000102030405060708090a0b0c0d0e00")
var key, _ = hex.DecodeString("000e0d0c0b0a09080706050403020100")

func TestAESEncryption(t *testing.T) {
	encrypted, err := AESEncryptWithIV([]byte(data), key, iv)
	if err != nil {
		t.Errorf(err.Error())
	}
	plain, err := AESDecryptWithIV(encrypted, key, iv)
	if err != nil {
		t.Errorf(err.Error())
	}
	if string(plain[:]) != data {
		t.Errorf("data mismatch after AES encrypt and decrypt")
	}
}

// Public key compressed
var publicKey, _ = hex.DecodeString("04866269bf6c2d71968ec46797b91b207affeea74dbba1f181ff354abbfbdfe9327c58d1c0681e328f555f5aa6ec2e7543baf2b3f89ce90720d617da710ce1ea93")
// Private key Wallet Import Format(WIF): 5KdBypVKceVrUNbWmxDJALGJ9fo9rwNYTjppps8gQb9C8VHUXzr
// Transfer to HEX with https://gobittest.appspot.com/PrivateKey
var privateKey, _ = hex.DecodeString("ee3231b5deea48b619814d72a6e1aa04a9f521df281afad5ada89f5393941b1c")

func TestEncryptMessage(t *testing.T) {
	encrypted, err := EncryptMessage(data, publicKey)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Println(encrypted)
	plain, err := DecryptMessage(encrypted, privateKey)
	if err != nil {
		t.Errorf(err.Error())
	}
	if data != plain {
		t.Errorf("data mismatch after encrypt and decrypt")
	}
}

func TestElectrumCompatible(t *testing.T) {
	electrumEncrypted := "QklFMQJdmY+9Ys1WjqANreLwXaau62N01r9lebJ9Rp7Az+XRMdNAVgg3J8EEVhni5gn2v+WOD59uDMDp0zY/xPT3IElReQo6XUCSMmgRgRtYl+TUEw=="
	plain, err := DecryptMessage(electrumEncrypted, privateKey)
	if err != nil {
		t.Errorf(err.Error())
	}
	if data != plain {
		t.Errorf("not compatible with Electrum/Electron Cash")
	}
}
