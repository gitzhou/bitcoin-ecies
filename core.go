package bitcoin_ecies

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"reflect"
)

func AppendPKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func StripPKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length%blockSize != 0 || length == 0 {
		return nil, errors.New("invalid padding length")
	}
	padding := int(data[length-1])
	if padding > blockSize {
		return nil, errors.New("invalid padding byte (large)")
	}
	for _, v := range data[len(data)-padding:] {
		if int(v) != padding {
			return nil, errors.New("invalid padding byte (inconsistent)")
		}
	}
	return data[:(length - padding)], nil
}

func AESEncryptWithIV(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data = AppendPKCS7Padding(data, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(data))
	blockModel.CryptBlocks(cipherText, data)
	return cipherText, nil
}

func AESDecryptWithIV(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plantText := make([]byte, len(data))
	blockModel.CryptBlocks(plantText, data)
	plantText, err = StripPKCS7Padding(plantText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plantText, nil
}

//
// ECIES encryption/decryption methods; AES-128-CBC with PKCS7 is used as the cipher; hmac-sha256 is used as the mac
//

func EncryptMessage(message string, pubKey []byte) (string, error) {
	publicKey, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		return "", err
	}
	// Generate an ephemeral EC private key in order to derive shared secret(ECDH key)
	ephemeralPrivateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	// Derive ECDH key
	x, y := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralPrivateKey.D.Bytes())
	ecdhKey := secp256k1.NewPublicKey(x, y).SerializeCompressed()
	// SHA512(ECDH_KEY), then we have
	// key_e and iv used in AES
	// key_m used in HMAC.SHA256
	sha512 := crypto.SHA512.New()
	sha512.Write(ecdhKey)
	key := sha512.Sum(nil)
	iv, keyE, keyM := key[0:16], key[16:32], key[32:]

	// Make the AES encryption
	cipherText, err := AESEncryptWithIV([]byte(message), keyE, iv)
	if err != nil {
		return "", err
	}
	ephemeralPublicKey := ephemeralPrivateKey.PubKey()
	// encrypted = magic_bytes(4 bytes) + ephemeral_public_key(33 bytes) + cipher(16 bytes at least)
	encrypted := append(append([]byte("BIE1"), ephemeralPublicKey.SerializeCompressed()...), cipherText...)
	// mac = HMAC_SHA256(encrypted) 32 bytes
	hmacSHA256 := hmac.New(crypto.SHA256.New, keyM)
	hmacSHA256.Write(encrypted)
	mac := hmacSHA256.Sum(nil)

	// Give out base64(encrypted + mac), at least 85 bytes
	return base64.StdEncoding.EncodeToString(append(encrypted, mac...)), nil
}

func DecryptMessage(message string, privKey []byte) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", nil
	}
	if len(encrypted) < 85 {
		return "", errors.New("invalid encrypted text: length")
	}
	magic := encrypted[:4]
	ephemeralPubKey := encrypted[4:37]
	cipherText := encrypted[37 : len(encrypted)-32]
	mac := encrypted[len(encrypted)-32:]

	if string(magic[:]) != "BIE1" {
		return "", errors.New("invalid cipher text: invalid magic bytes")
	}
	privateKey, _ := secp256k1.PrivKeyFromBytes(privKey)
	ephemeralPublicKey, err := secp256k1.ParsePubKey(ephemeralPubKey)
	if err != nil {
		return "", err
	}
	// Restore ECDH key
	x, y := ephemeralPublicKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())
	ecdhKey := secp256k1.NewPublicKey(x, y).SerializeCompressed()
	// Restore key_e, iv and key_m
	sha512 := crypto.SHA512.New()
	sha512.Write(ecdhKey)
	key := sha512.Sum(nil)
	iv, keyE, keyM := key[0:16], key[16:32], key[32:]
	// Verify mac
	hmacSHA256 := hmac.New(crypto.SHA256.New, keyM)
	hmacSHA256.Write(encrypted[:len(encrypted)-32])
	macRecalculated := hmacSHA256.Sum(nil)
	if !reflect.DeepEqual(mac, macRecalculated) {
		return "", errors.New("incorrect password")
	}

	// Make the AES decryption
	plain, err := AESDecryptWithIV(cipherText, keyE, iv)
	if err != nil {
		return "", err
	}
	return string(plain[:]), nil
}
