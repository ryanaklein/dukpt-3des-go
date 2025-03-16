package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
)

func main() {
	bdk, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	ksn, _ := hex.DecodeString("88888851400018400003")

	createIpek(bdk, ksn)

}

func createIpek(bdk, ksn []byte) {

	ksnMask, _ := hex.DecodeString("FFFFFFFFFFFFFFE00000")
	keyMask, _ := hex.DecodeString("C0C0C0C000000000C0C0C0C000000000")

	ksn, _ = bitwiseAndBytes(ksn, ksnMask)
	ksn = rightShiftBytes(ksn, 16)

	ksn = trimLeadingZeros(ksn)

	cipherTextLeft := tripleDesEncrypt(bdk, ksn)
	xOrKey, _ := bitwiseXorBytes(bdk, keyMask)
	cipherTextRight := tripleDesEncrypt(xOrKey, ksn)

	result := append(cipherTextLeft, cipherTextRight...)

	fmt.Printf("%x\n", result)

}

func tripleDesEncrypt(key, plaintext []byte) []byte {

	if len(plaintext)%des.BlockSize != 0 {
		plaintext = padPKCS7(plaintext, des.BlockSize)
	}

	var tripleDESKey []byte
	tripleDESKey = append(tripleDESKey, key...)
	tripleDESKey = append(tripleDESKey, key[:8]...)

	block, err := des.NewTripleDESCipher(tripleDESKey)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}

func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func bitwiseAndBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("input slices must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] & b[i]
	}
	return result, nil
}

func bitwiseOrBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("input slices must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] | b[i]
	}
	return result, nil
}

func bitwiseXorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("input slices must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func bitwiseNotBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = ^data[i]
	}
	return result
}

func leftShiftBytes(data []byte, shift uint) []byte {
	if shift == 0 || len(data) == 0 {
		return data
	}

	// Create a new slice to store the result
	result := make([]byte, len(data))

	// Calculate the byte and bit shifts
	byteShift := int(shift / 8) // Number of whole bytes to shift
	bitShift := shift % 8       // Number of bits to shift within a byte

	for i := 0; i < len(data); i++ {
		if i+byteShift < len(data) {
			// Shift current byte by bitShift and add overflow from the next byte
			result[i] = data[i+byteShift] << bitShift
			if i+byteShift+1 < len(data) && bitShift > 0 {
				result[i] |= data[i+byteShift+1] >> (8 - bitShift)
			}
		}
	}

	return result
}

func rightShiftBytes(data []byte, shift uint) []byte {
	if shift == 0 || len(data) == 0 {
		return data
	}

	result := make([]byte, len(data))
	byteShift := int(shift / 8)
	bitShift := shift % 8

	for i := len(data) - 1; i >= 0; i-- {
		if i-byteShift >= 0 {
			result[i] = data[i-byteShift] >> bitShift
			if i-byteShift-1 >= 0 && bitShift > 0 {
				result[i] |= data[i-byteShift-1] << (8 - bitShift)
			}
		}
	}
	return result
}

func trimLeadingZeros(data []byte) []byte {
	for i, b := range data {
		if b != 0x00 { // Find the first non-zero byte
			return data[i:] // Slice from the first non-zero byte onward
		}
	}
	return []byte{} // Return an empty slice if all bytes are zero
}
