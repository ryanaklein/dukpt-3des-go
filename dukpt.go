package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

var keyMask []byte
var ksnMask []byte

func main() {

	keyMask, _ = hex.DecodeString("C0C0C0C000000000C0C0C0C000000000")
	ksnMask, _ = hex.DecodeString("FFFFFFFFFFFFFFE00000")

	bdk, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	ksn, _ := hex.DecodeString("FFFF9876543210E00008")

	ipek := createIPEK(bdk, ksn)
	fmt.Printf("ipek: %x\n", ipek)
	createSessionKey(ipek, ksn)

}

func createIPEK(bdk, ksn []byte) []byte {

	ksn, _ = bitwiseAndBytes(ksn, ksnMask)
	ksn = rightShiftBytes(ksn, 16)

	ksn = trimLeadingZeros(ksn)

	cipherTextLeft := tripleDesEncrypt(bdk, ksn)
	xOrKey, _ := bitwiseXorBytes(bdk, keyMask)
	cipherTextRight := tripleDesEncrypt(xOrKey, ksn)

	result := append(cipherTextLeft, cipherTextRight...)

	return result

}

func createSessionKey(ipek, ksn []byte) {

	sessionKeyMask, _ := hex.DecodeString("00000000000000FF00000000000000FF")

	fmt.Printf("ipek: %x\n", ipek)

	key := deriveKey(ipek, ksn)

	fmt.Printf("final key: %x\n", key)

	sessionKey, _ := bitwiseXorBytes(key, sessionKeyMask)

	fmt.Printf("session key: %x\n", sessionKey)

}

func deriveKey(ipek, ksn []byte) []byte {

	ksnReg, _ := bitwiseAndBytes(ksn, ksnMask)

	fmt.Printf("initial : %x\n", ksnReg)

	currentKey := ipek

	transactionCounter := extractTransactionCounter(ksn)
	const mask uint32 = 0x1FFFFF

	for shiftReg := 0x100000; shiftReg > 0; shiftReg >>= 1 {
		if shiftReg&int(transactionCounter)&int(mask) > 0 {
			ksnReg, _ = bitwiseOrBytes(ksnReg, uint32To10ByteSlice(uint32(shiftReg)))
			fmt.Printf("current key: %x\n", currentKey)
			fmt.Printf("ksnReg: %x\n", ksnReg)
			currentKey = generateKey(currentKey, ksnReg)
			print("\n\n")
		}

	}

	return currentKey

}

func generateKey(key, ksn []byte) []byte {

	maskedKey, _ := bitwiseXorBytes(key, keyMask)

	encryptLeft := encryptRegister(maskedKey, ksn)
	encryptRight := encryptRegister(key, ksn)

	fmt.Printf("encrypt left: %x\n", encryptLeft)
	fmt.Printf("encrypt right: %x\n", encryptRight)

	// result, _ := bitwiseOrBytes(leftShiftBytes(encryptLeft, 64), encryptRight)

	result := append(encryptLeft, encryptRight...)

	fmt.Printf("encrypt result: %x\n", result)

	return result

}

func encryptRegister(key, reg []byte) []byte {

	fmt.Printf("key: %x\n", key)

	keyLeft := key[:8]
	keyRight := key[8:]

	fmt.Printf("key left: %x\n", keyLeft)
	fmt.Printf("key right: %x\n", keyRight)
	fmt.Printf("reg: %x\n", reg)

	keyReg, _ := bitwiseXorBytes(keyRight, reg[2:])

	fmt.Printf("key reg: %x\n", keyReg)

	tripleDESResult := desEncrypt(keyLeft, keyReg)

	// tripleDESResult := tripleDesEncrypt(keyLeft, keyReg)

	fmt.Printf("3des result: %x\n", tripleDESResult)

	encryptionResult, _ := bitwiseXorBytes(keyRight, tripleDESResult)

	fmt.Printf("encryption result: %x\n", encryptionResult)

	print("\n")

	return encryptionResult

}

func tripleDesEncrypt(key, plaintext []byte) []byte {

	if len(plaintext)%des.BlockSize != 0 {
		plaintext = padPKCS7(plaintext, des.BlockSize)
	}

	var tripleDESKey []byte

	if len(key) == 8 {
		tripleDESKey = append(append(key, key...), key...)
	}

	if len(key) == 16 {
		tripleDESKey = append(tripleDESKey, key...)
		tripleDESKey = append(tripleDESKey, key[:8]...)
	}

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

func desEncrypt(key, plaintext []byte) []byte {

	if len(plaintext)%des.BlockSize != 0 {
		plaintext = padPKCS7(plaintext, des.BlockSize)
	}

	// var tripleDESKey []byte
	// tripleDESKey = append(tripleDESKey, key...)
	// tripleDESKey = append(tripleDESKey, key[:8]...)

	block, err := des.NewCipher(key)
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

func extractTransactionCounter(ksn []byte) uint32 {
	// Ensure the KSN is at least 3 bytes long
	if len(ksn) < 3 {
		panic("KSN must be at least 3 bytes long")
	}

	// The transaction counter is in the last 20 bits (3 bytes)
	// Mask out the upper 4 bits of the first byte of the last 3 bytes
	return uint32(ksn[len(ksn)-3]&0x1F)<<16 | // Mask upper 4 bits and shift to the most significant position
		uint32(ksn[len(ksn)-2])<<8 | // Take the middle byte and shift it
		uint32(ksn[len(ksn)-1]) // Add the least significant byte
}

func uint32To10ByteSlice(value uint32) []byte {
	// Create a 10-byte slice initialized to zeros
	result := make([]byte, 10)

	// Convert the uint32 value to 4 bytes in big-endian order
	binary.BigEndian.PutUint32(result[6:], value)

	// Return the resulting 10-byte slice
	return result
}

func repeatBytesTo16(key []byte) []byte {
	if len(key) != 8 {
		panic("Key must be 8 bytes long")
	}

	// Duplicate the 8-byte slice to make it 16 bytes
	repeatedKey := append(key, key...)

	return repeatedKey
}
