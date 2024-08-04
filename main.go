package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
)

// GenerateRSAKeyPair generates a new RSA key pair.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// EncryptWithPublicKey encrypts data using the public key.
func EncryptWithPublicKey(pub *rsa.PublicKey, msg []byte) (string, error) {
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// DecryptWithPrivateKey decrypts data using the private key.
func DecryptWithPrivateKey(priv *rsa.PrivateKey, encryptedMsg string) ([]byte, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedMsg)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedBytes, nil)
}

// EncryptAES encrypts the plaintext using AES.
func EncryptAES(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts the ciphertext using AES.
func DecryptAES(ciphertext string, key []byte) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := decoded[:nonceSize]
	ciphertextBytes := decoded[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ExportRSAPublicKeyToPEM exports the RSA public key to PEM format.
func ExportRSAPublicKeyToPEM(pub *rsa.PublicKey) []byte {
	pubASN1 := x509.MarshalPKCS1PublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
}

// ImportRSAPublicKeyFromPEM imports an RSA public key from PEM format.
func ImportRSAPublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func main() {
	// Generate RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Print the public key in PEM format
	fmt.Printf("Public Key:\n%s\n", ExportRSAPublicKeyToPEM(publicKey))

	// Generate a random AES key
	aesKey := make([]byte, 32) // AES-256 requires a 32-byte key
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		log.Fatalf("Error generating AES key: %v", err)
	}

	// Encrypt the AES key with the recipient's public RSA key
	encryptedAESKey, err := EncryptWithPublicKey(publicKey, aesKey)
	if err != nil {
		log.Fatalf("Error encrypting AES key: %v", err)
	}
	fmt.Printf("Encrypted AES Key: %s\n", encryptedAESKey)

	// Encrypt the message using AES
	plaintext := "Hello, this is a secret message!"
	encryptedMessage, err := EncryptAES([]byte(plaintext), aesKey)
	if err != nil {
		log.Fatalf("Error encrypting message: %v", err)
	}
	fmt.Printf("Encrypted Message: %s\n", encryptedMessage)

	// The recipient would now decrypt the AES key with their private RSA key
	decryptedAESKey, err := DecryptWithPrivateKey(privateKey, encryptedAESKey)
	if err != nil {
		log.Fatalf("Error decrypting AES key: %v", err)
	}

	// Decrypt the message using the decrypted AES key
	decryptedMessage, err := DecryptAES(encryptedMessage, decryptedAESKey)
	if err != nil {
		log.Fatalf("Error decrypting message: %v", err)
	}
	fmt.Printf("Decrypted Message: %s\n", decryptedMessage)
}
