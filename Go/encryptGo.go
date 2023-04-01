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
	key := "PLACE-KEY-HERE" //32 chars long
	fmt.Println("Key = %s.", key)

	//Place shellcode here without 0x and comma values
	shellcode, errShellcode := hex.DecodeString("PLACE-SHELLCODE-HERE")
	fmt.Println("Original bytes = '%s'.", shellcode)

	encryptedBytes, err := EncryptByteArray([]byte(key), shellcode)
	if errShellcode != nil {
		fmt.Println("Could not encrypt the string: %s", err.Error())
	}

	encodedString := hex.EncodeToString(encryptedBytes)

	fmt.Println("Encrypted bytes = '%s'.", encodedString)
}
