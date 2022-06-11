// Problem set 01: Hash based signatures.

// A lot of this lab is set up and templated for you to get used to
// what may be an unfamiliar language (Go).  Go is syntactically
// similar to C / C++ in many ways, including comments.

// In this pset, you need to build a hash based signature system.  We'll use sha256
// as our hash function, and Lamport's simple signature design.

// Currently this compiles but doesn't do much.  You need to implement parts which
// say "your code here".  It also could be useful to make your own functions or
// methods on existing structs, espectially in the forge.go file.

// If you run `go test` and everything passes, you're all set.

// There's probably some way to get it to pass the tests without making an actual
// functioning signature scheme, but I think that would be harder than just doing
// it the right way :)

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {

	// Define your message
	textString := "1"
	fmt.Printf("%s\n", textString)

	// convert message into a block
	m := GetMessageFromString(textString)
	fmt.Printf("%x\n", m[:])

	// generate keys
	sec, pub, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	// print pubkey.
	fmt.Printf("pub:\n%s\n", pub.ToHex())

	// sign message
	sig1 := Sign(m, sec)
	fmt.Printf("sig1:\n%s\n", sig1.ToHex())

	// verify signature
	worked := Verify(m, pub, sig1)

	// done
	fmt.Printf("Verify worked? %v\n", worked)

	// Forge signature
	msgString, sig, err := Forge()
	if err != nil {
		panic(err)
	}

	fmt.Printf("forged msg: %s sig: %s\n", msgString, sig.ToHex())

	return
}

// Signature systems have 3 functions: GenerateKey(), Sign(), and Verify().
// We'll also define the data types: SecretKey, PublicKey, Message, Signature.

// --- Types

// A block of data is always 32 bytes long; we're using sha256 and this
// is the size of both the output (defined by the hash function) and our inputs
type Block [32]byte

type SecretKey struct {
	ZeroPre [256]Block
	OnePre  [256]Block
}

type PublicKey struct {
	ZeroHash [256]Block
	OneHash  [256]Block
}

// --- Methods on PublicKey type

// ToHex gives a hex string for a PublicKey. no newline at the end
func (self PublicKey) ToHex() string {
	// format is zerohash 0...255, onehash 0...255
	var s string
	for _, zero := range self.ZeroHash {
		s += zero.ToHex()
	}
	for _, one := range self.OneHash {
		s += one.ToHex()
	}
	return s
}

// HexToPubkey takes a string from PublicKey.ToHex() and turns it into a pubkey
// will return an error if there are non hex characters or if the lenght is wrong.
func HexToPubkey(s string) (PublicKey, error) {
	var p PublicKey

	expectedLength := 256 * 2 * 64 // 256 blocks long, 2 rows, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return p, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range p.ZeroHash {
		p.ZeroHash[i] = BlockFromByteSlice(buf.Next(32))
	}
	for i, _ := range p.OneHash {
		p.OneHash[i] = BlockFromByteSlice(buf.Next(32))
	}

	return p, nil
}

// A message to be signed is just a block.
type Message Block

// --- Methods on the Block type

// ToHex returns a hex encoded string of the block data, with no newlines.
func (self Block) ToHex() string {
	return fmt.Sprintf("%064x", self[:])
}

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

// IsPreimage returns true if the block is a preimage of the argument.
// For example, if Y = hash(X), then X.IsPreimage(Y) will return true,
// and Y.IsPreimage(X) will return false.
func (self Block) IsPreimage(arg Block) bool {
	return self.Hash() == arg
}

// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

// A signature consists of 32 blocks.  It's a selective reveal of the private
// key, according to the bits of the message.
type Signature struct {
	Preimage [256]Block
}

// ToHex returns a hex string of a signature
func (self Signature) ToHex() string {
	var s string
	for _, b := range self.Preimage {
		s += b.ToHex()
	}

	return s
}

// HexToSignature is the same idea as HexToPubkey, but half as big.  Format is just
// every block of the signature in sequence.
func HexToSignature(s string) (Signature, error) {
	var sig Signature

	expectedLength := 256 * 64 // 256 blocks long, 1 row, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return sig, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return sig, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range sig.Preimage {
		sig.Preimage[i] = BlockFromByteSlice(buf.Next(32))
	}
	return sig, nil
}

// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

// --- Functions

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (SecretKey, PublicKey, error) {
	// initialize SecretKey variable 'sec'.  Starts with all 00 bytes.
	var sec SecretKey
	var pub PublicKey

	// Generate Sec key: random number of 256 zero blocks and 256 One Blocks, each block is 32 bytes(256 bits)

	// Generate PubKey, for each block generate a hash value of 32 bytes as well.
	zeroBlock := make([]byte, 32, 32)
	oneBlock := make([]byte, 32, 32)

	for i := 0; i < 256; i++ {

		_, err := rand.Read(zeroBlock)
		_, err1 := rand.Read((oneBlock))
		if err != nil {
			return sec, pub, err
		}
		if err1 != nil {
			return sec, pub, err1
		}
		zeroBlockcopied := copy(sec.ZeroPre[i][:], zeroBlock[:])
		oneBlockcopied := copy(sec.OnePre[i][:], oneBlock[:])
		if zeroBlockcopied != 32 || oneBlockcopied != 32 {
			return sec, pub, fmt.Errorf("In round %d, cpy from slice to array not completed, zero blocked copied bytes %d, one block copied bytes %d \n", i, zeroBlockcopied, oneBlockcopied)
		}

		//fmt.Printf("Init round %d\n", i)
		pub.ZeroHash[i] = sha256.Sum256(zeroBlock[:])
		pub.OneHash[i] = sha256.Sum256(oneBlock[:])

		// fmt.Printf("Zero Block data 32 Bytes: %x\n", sec.ZeroPre[i])
		// fmt.Printf("Zero Block hash Bytes: %x\n", pub.ZeroHash[i])
		// fmt.Printf("One Block 32 Bytes: %x\n", sec.OnePre[i])
		// fmt.Printf("One Block hash Bytes: %x\n", pub.OneHash[i])
	}

	return sec, pub, nil
}

// Sign takes a message and secret key, and returns a signature.
func Sign(msg Message, sec SecretKey) Signature {
	var sig Signature

	for i := 0; i < 32; i++ {
		// loop over every bytes in the message, saying b.

		// loop 8 times. Mask initialized as 0xA0.
		// calculates the value of b & Mask, if byte & Mask == Mask it mean the corrsponding bit is 1.
		Mask := 0x80
		for j := 0; j < 8; j++ {
			if msg[i]&byte(Mask) == byte(Mask) {
				// The (8i+j)'th bit is 1
				sig.Preimage[8*i+j] = sec.OnePre[8*i+j]
			} else {
				sig.Preimage[8*i+j] = sec.ZeroPre[8*i+j]
			}
			Mask = Mask >> 1
		}
	}
	return sig
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
func Verify(msg Message, pub PublicKey, sig Signature) bool {

	for i := 0; i < 32; i++ {
		// loop over every bytes in the message, saying b.

		// loop 8 times. Mask initialized as 0xA0.
		// calculates the value of b & Mask, if byte & Mask == Mask it mean the corrsponding bit is 1.
		Mask := 0x80
	ThisByte:
		for j := 0; j < 8; j++ {
			original32bytesNumber := sig.Preimage[8*i+j]
			original32bytesHash := sha256.Sum256(original32bytesNumber[:])
			if msg[i]&byte(Mask) == byte(Mask) {
				// The (8i+j)'th bit is 1
				// get the original number(signature) from preimage.onepre.
				if bytes.Equal(original32bytesHash[:], pub.OneHash[8*i+j][:]) {
					//fmt.Printf("number in 265, idx %d found in OneBlock, match the hash of num: %x", 8*i+j, pub.OneHash[8*i+j])
					Mask = Mask >> 1
					continue ThisByte
				} else {
					return false
				}
			} else {
				if bytes.Equal(original32bytesHash[:], pub.ZeroHash[8*i+j][:]) {
					//fmt.Printf("number in 265, idx %d found in ZeroBlock, match the hash of num: %x", 8*i+j, pub.ZeroHash[8*i+j])
					Mask = Mask >> 1
					continue ThisByte
				} else {
					return false
				}
			}

		}

	}

	return true
}
