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

// Factories

func Standard(password, salt string) StandardEncryptor {
	return StandardEncryptor{key: newPBKDF2WithHmacSHA1(password, salt)}
}

func Stronger(password, salt string) StrongerEncryptor {
	return StrongerEncryptor{key: newPBKDF2WithHmacSHA1(password, salt)}
}

func Text(password, salt string) TextEncryptor {
	return TextEncryptor{standard: Standard(password, salt)}
}

func QueryableText(password, salt string) QueryableTextEncryptor {
	return QueryableTextEncryptor{key: newPBKDF2WithHmacSHA1(password, salt)}
}

func Delux(password, salt string) DeluxEncryptor {
	return DeluxEncryptor{stronger: Stronger(password, salt)}
}

// Encryptors

type StandardEncryptor struct {
	key []byte
}

type StrongerEncryptor struct {
	key []byte
}

type TextEncryptor struct {
	standard StandardEncryptor
}

type QueryableTextEncryptor struct {
	key []byte
}

type DeluxEncryptor struct {
	stronger StrongerEncryptor
}

func (e StandardEncryptor) Encrypt(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Seed(time.Now().UnixNano())
	rand.Read(iv)
	ciphertext := encryptSpringAesBytes(data, iv, e.key, cipherModeCBC)
	return append(iv, ciphertext...)
}

func (e StandardEncryptor) Decrypt(data []byte) []byte {
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	return decryptSpringAesBytes(ciphertext, iv, e.key, cipherModeCBC)
}

func (e StrongerEncryptor) Encrypt(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Seed(time.Now().UnixNano())
	rand.Read(iv)
	ciphertext := encryptSpringAesBytes(data, iv, e.key, cipherModeGCM)
	return append(iv, ciphertext...)
}

func (e StrongerEncryptor) Decrypt(data []byte) []byte {
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	return decryptSpringAesBytes(ciphertext, iv, e.key, cipherModeGCM)
}

func (e TextEncryptor) Encrypt(data string) string {
	dataBytes := []byte(data)
	encryptedData := e.standard.Encrypt(dataBytes)
	return hex.EncodeToString(encryptedData)
}

func (e TextEncryptor) Decrypt(data string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	decryptedData := e.standard.Decrypt(dataBytes)
	return string(decryptedData)
}

func (e DeluxEncryptor) Encrypt(data string) string {
	dataBytes := []byte(data)
	encryptedData := e.stronger.Encrypt(dataBytes)
	return hex.EncodeToString(encryptedData)
}

func (e DeluxEncryptor) Decrypt(data string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	decryptedData := e.stronger.Decrypt(dataBytes)
	return string(decryptedData)
}

func (e QueryableTextEncryptor) Encrypt(data string) string {
	dataBytes := []byte(data)
	iv := make([]byte, aes.BlockSize)
	ciphertext := encryptSpringAesBytes(dataBytes, iv, e.key, cipherModeCBC)
	return hex.EncodeToString(ciphertext)
}

func (e QueryableTextEncryptor) Decrypt(data string) string {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	decryptedData := decryptSpringAesBytes(dataBytes, iv, e.key, cipherModeCBC)
	return string(decryptedData)
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
