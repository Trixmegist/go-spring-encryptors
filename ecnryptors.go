package encryptors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	cipherModeCBC = iota
	cipherModeGCM
)

type SpringEncryptor struct {
	key []byte
}

func (se SpringEncryptor) EncryptStandard(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Seed(time.Now().UnixNano())
	rand.Read(iv)
	ciphertext := encryptSpringAesBytes(data, iv, se.key, cipherModeCBC)
	return append(iv, ciphertext...)
}

func (se SpringEncryptor) DecryptStandard(data []byte) []byte {
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	return decryptSpringAesBytes(ciphertext, iv, se.key, cipherModeCBC)
}

func (se SpringEncryptor) EncryptStronger(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Seed(time.Now().UnixNano())
	rand.Read(iv)
	ciphertext := encryptSpringAesBytes(data, iv, se.key, cipherModeGCM)
	return append(iv, ciphertext...)
}

func (se SpringEncryptor) DecryptStronger(data []byte) []byte {
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	return decryptSpringAesBytes(ciphertext, iv, se.key, cipherModeGCM)
}

func (se SpringEncryptor) EncryptText(data string) string {
	dataBytes := []byte(data)
	encryptedData := se.EncryptStandard(dataBytes)
	return hex.EncodeToString(encryptedData)
}

func (se SpringEncryptor) DecryptText(data string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	decryptedData := se.DecryptStandard(dataBytes)
	return string(decryptedData)
}

func (se SpringEncryptor) EncryptDelux(data string) string {
	dataBytes := []byte(data)
	encryptedData := se.EncryptStronger(dataBytes)
	return hex.EncodeToString(encryptedData)
}

func (se SpringEncryptor) DecryptDelux(data string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	decryptedData := se.DecryptStronger(dataBytes)
	return string(decryptedData)
}

func (se SpringEncryptor) EncryptQueryableText(data string) string {
	dataBytes := []byte(data)
	iv := make([]byte, aes.BlockSize)
	ciphertext := encryptSpringAesBytes(dataBytes, iv, se.key, cipherModeCBC)
	return hex.EncodeToString(ciphertext)
}

func (se SpringEncryptor) DecryptQueryableText(data string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	decryptedData := decryptSpringAesBytes(dataBytes, iv, se.key, cipherModeCBC)
	return string(decryptedData)
}

func NewSpringEncryptor(password, salt string) SpringEncryptor {
	return SpringEncryptor{key: newPBKDF2WithHmacSHA1(password, salt)}
}

func newPBKDF2WithHmacSHA1(password, salt string) []byte {
	passwordBytes := []byte(password)
	saltBytes, _ := hex.DecodeString(salt)
	return pbkdf2.Key(passwordBytes, saltBytes, 1024, 32, sha1.New)
}

func encryptSpringAesBytes(plaintext, iv, key []byte, cipherMode int) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	switch cipherMode {
	case cipherModeCBC:
		mode := cipher.NewCBCEncrypter(block, iv)
		paddedPlaintext := PKCS5Pad(plaintext, mode.BlockSize())
		mode.CryptBlocks(paddedPlaintext, paddedPlaintext)
		return paddedPlaintext
	case cipherModeGCM:
		gcm, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			panic(err)
		}
		result := gcm.Seal(nil, iv, plaintext, nil)
		return result
	default:
		panic(fmt.Sprintf("Unknown cipherMode '%d'", cipherMode))
	}
}

func decryptSpringAesBytes(ciphertext, iv, key []byte, cipherMode int) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	switch cipherMode {
	case cipherModeCBC:
		if len(ciphertext) < aes.BlockSize {
			panic("ciphertext too short")
		}
		if len(ciphertext)%aes.BlockSize != 0 {
			panic("ciphertext is not a multiple of the block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(ciphertext, ciphertext)
		return PKCS5Unpad(ciphertext)
	case cipherModeGCM:
		gcm, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			panic(err)
		}
		result, err := gcm.Open(nil, iv, ciphertext, nil)
		if err != nil {
			panic(err)
		}
		return result
	default:
		panic(fmt.Sprintf("Unknown cipherMode '%d'", cipherMode))
	}
}

func PKCS5Pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Unpad(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
