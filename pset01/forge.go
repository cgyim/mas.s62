package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
)

/*
A note about the provided keys and signatures:
the provided pubkey and signature, as well as "HexTo___" functions may not work
with all the different implementations people could built.  Specifically, they
are tied to an endian-ness.  If, for example, you decided to encode your public
keys as (according to the diagram in the slides) up to down, then left to right:
<bit 0, row 0> <bit 0, row 1> <bit 1, row 0> <bit 1, row 1> ...

then it won't work with the public key provided here, because it was encoded as
<bit 0, row 0> <bit 1, row 0> <bit 2, row 0> ... <bit 255, row 0> <bit 0, row 1> ...
(left to right, then up to down)

so while in class I said that any decisions like this would work as long as they
were consistent... that's not actually the case!  Because your functions will
need to use the same ordering as the ones I wrote in order to create the signatures
here.  I used what I thought was the most straightforward / simplest encoding, but
endian-ness is something of a tabs-vs-spaces thing that people like to argue
about :).

So for clarity, and since it's not that obvious from the HexTo___ decoding
functions, here's the order used:

secret keys and public keys:
all 256 elements of row 0, most significant bit to least significant bit
(big endian) followed by all 256 elements of row 1.  Total of 512 blocks
of 32 bytes each, for 16384 bytes.
For an efficient check of a bit within a [32]byte array using this ordering,
you can use:
    arr[i/8]>>(7-(i%8)))&0x01
where arr[] is the byte array, and i is the bit number; i=0 is left-most, and
i=255 is right-most.  The above statement will return a 1 or a 0 depending on
what's at that bit location.

Messages: messages are encoded the same way the sha256 function outputs, so
nothing to choose there.

Signatures: Signatures are also read left to right, MSB to LSB, with 256 blocks
of 32 bytes each, for a total of 8192 bytes.  There is no indication of whether
the provided preimage is from the 0-row or the 1-row; the accompanying message
hash can be used instead, or both can be tried.  This again interprets the message
hash in big-endian format, where
    message[i/8]>>(7-(i%8)))&0x01
can be used to determine which preimage block to reveal, where message[] is the
message to be signed, and i is the sequence of bits in the message, and blocks
in the signature.

Hopefully people don't have trouble with different encoding schemes.  If you
really want to use your own method which you find easier to work with or more
intuitive, that's OK!  You will need to re-encode the key and signatures provided
in signatures.go to match your ordering so that they are valid signatures with
your system.  This is probably more work though and I recommend using the big
endian encoding described here.

*/

// Forge is the forgery function, to be filled in and completed.  This is a trickier
// part of the assignment which will require the computer to do a bit of work.
// It's possible for a single core or single thread to complete this in a reasonable
// amount of time, but may be worthwhile to write multithreaded code to take
// advantage of multi-core CPUs.  For programmers familiar with multithreaded code
// in golang, the time spent on parallelizing this code will be more than offset by
// the CPU time speedup.  For programmers with access to 2-core or below CPUs, or
// who are less familiar with multithreaded code, the time taken in programming may
// exceed the CPU time saved.  Still, it's all about learning.
// The Forge() function doesn't take any inputs; the inputs are all hard-coded into
// the function which is a little ugly but works OK in this assigment.
// The input public key and signatures are provided in the "signatures.go" file and
// the code to convert those into the appropriate data structures is filled in
// already.
// Your job is to have this function return two things: A string containing the
// substring "forge" as well as your name or email-address, and a valid signature
// on the hash of that ascii string message, from the pubkey provided in the
// signatures.go file.
// The Forge function is tested by TestForgery() in forge_test.go, so if you
// run "go test" and everything passes, you should be all set.
func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	msgString := "zhejyan@microsoft.com's forge"
	msgBuf := []byte(msgString)
	var sig Signature

	var privateKey SecretKey
	zeroPreIsRevealed := make(map[int]bool, 256)
	OnePreIsRevealed := make(map[int]bool, 256)
	for idx, block := range sig1.Preimage {
		if block.Hash() == pub.ZeroHash[idx] {
			//fmt.Printf("sig1 image[%d] number Hash match zero Hash, select zero\n", idx)
			privateKey.ZeroPre[idx] = block
			zeroPreIsRevealed[idx] = true
		} else {
			if block.Hash() == pub.OneHash[idx] {
				//fmt.Printf("sig1 image[%d] number Hash match One Hash, select One\n", idx)
				privateKey.OnePre[idx] = block
				OnePreIsRevealed[idx] = true
			} else {
				panic(errors.New(fmt.Sprintf("sig1 image[%d] hash %s does not match One or Zero!\n", idx, block.Hash().ToHex())))
			}
		}
	}

	for idx, block := range sig2.Preimage {

		if block.Hash() == pub.ZeroHash[idx] {
			//fmt.Printf("sig2 image[%d] number Hash match zero Hash, select zero\n", idx)
			privateKey.ZeroPre[idx] = block
			zeroPreIsRevealed[idx] = true
		} else {
			if block.Hash() == pub.OneHash[idx] {
				//fmt.Printf("sig2 image[%d] number Hash match One Hash, select One\n", idx)
				privateKey.OnePre[idx] = block
				OnePreIsRevealed[idx] = true
			} else {
				panic(errors.New(fmt.Sprintf("sig2 image[%d] hash %s does not match One or Zero!\n", idx, block.Hash().ToHex())))
			}
		}
	}

	for idx, block := range sig3.Preimage {

		if block.Hash() == pub.ZeroHash[idx] {
			//fmt.Printf("sig3 image[%d] number Hash match zero Hash, select zero\n", idx)
			privateKey.ZeroPre[idx] = block
			zeroPreIsRevealed[idx] = true
		} else {
			if block.Hash() == pub.OneHash[idx] {
				//fmt.Printf("sig3 image[%d] number Hash match One Hash, select One\n", idx)
				privateKey.OnePre[idx] = block
				OnePreIsRevealed[idx] = true
			} else {
				panic(errors.New(fmt.Sprintf("sig3 image[%d] hash %s does not match One or Zero!\n", idx, block.Hash().ToHex())))
			}
		}
	}

	for idx, block := range sig4.Preimage {

		if block.Hash() == pub.ZeroHash[idx] {
			//fmt.Printf("sig4 image[%d] number Hash match zero Hash, select zero\n", idx)
			privateKey.ZeroPre[idx] = block
			zeroPreIsRevealed[idx] = true
		} else {
			if block.Hash() == pub.OneHash[idx] {
				//fmt.Printf("sig4 image[%d] number Hash match One Hash, select One\n", idx)
				privateKey.OnePre[idx] = block
				OnePreIsRevealed[idx] = true
			} else {
				panic(errors.New(fmt.Sprintf("sig4 image[%d] hash %s does not match One or Zero!\n", idx, block.Hash().ToHex())))
			}
		}
	}

	// check, for each i range from 0 to 255, at least one block(either zero or one) pre image should be revealed.
	for k := 0; k < 256; k++ {
		_, ok1 := zeroPreIsRevealed[k]
		_, ok2 := OnePreIsRevealed[k]
		if !(ok1 || ok2) {
			panic(fmt.Errorf("panic. idx[%d], both zero pre image and one pre image are not revealed.\n", k))
		}
	}

	corenum := runtime.NumCPU()
	complete := make(chan string)

	buf1 := make([]byte, 27)
	buf2 := make([]byte, 29)

	for n := 0; n < corenum; n++ {
		go func(TaskId int) {
		TryNextMessage:
			for {
				_, err1 := rand.Read(buf1)
				_, err2 := rand.Read(buf2)
				if err1 != nil || err2 != nil {

					fmt.Println("gen rand error ===>")
				}

				messageProcessing := append(append(buf1, msgBuf...), buf2...)
				//fmt.Printf("Processing Msg [%s]\n", hex.EncodeToString(messageProcessing))
				msgBlock := sha256.Sum256(messageProcessing)
			UseImageByCheckingBit:
				for x := 0; x < 256; x++ {
					if msgBlock[x/8]>>(7-(x%8))&0x01 == 0x01 {
						// the i'th bit is 1
						if _, ok := OnePreIsRevealed[x]; ok {
							//fmt.Printf("Task Id: %d , idx: [%d], bit 1 and onePre is revealed, looks good.\n", TaskId, x)
							continue UseImageByCheckingBit
						} else {
							//fmt.Printf("Task Id: %d , processing msg: %s, bit idx: [%d], found 1 and onePre is not revealed, looks not good, going next.\n", TaskId, messageProcessing, x)
							// should use one pre but one pre does not exist, in this case we select to next msg
							messageProcessing = nil
							continue TryNextMessage
						}
					} else {
						if msgBlock[x/8]>>(7-(x%8))&0x01 != 0x00 {
							panic(fmt.Errorf("Task Id: %d, idx: [%d], bit not 0 or 1\n", TaskId, x))
						}
						// the i'th bit is 0
						if _, ok := zeroPreIsRevealed[x]; ok {
							//fmt.Printf("Task Id: %d , idx: [%d], bit 0 and zeroPre is revealed, looks good.\n", TaskId, x)
							continue UseImageByCheckingBit
						} else {
							//fmt.Printf("Task Id: %d , processing msg: %s, bit idx: [%d], found 0 and zeroPre is not revealed, looks not good, going next.\n", TaskId, messageProcessing, x)
							// should use one pre but one pre does not exist, in this case we select to next msg
							messageProcessing = nil
							continue TryNextMessage
						}
					}
				}

				fmt.Printf("We successfully get the forgery msg! %s\n", string(messageProcessing))
				complete <- string(messageProcessing)
			}
		}(n)

	}

	msg := <-complete
	msgBlock := GetMessageFromString(msg)
	for x := 0; x < 256; x++ {
		if msgBlock[x/8]>>(7-(x%8))&0x01 == 0x01 {
			// the i'th bit is 1
			fmt.Printf("composing forged signature: select one pre, Idx: [%d]\n", x)
			sig.Preimage[x] = privateKey.OnePre[x]
		} else {
			// the i'th bit is 0
			fmt.Printf("composing forged signature: select zero pre, Idx: [%d]\n", x)
			sig.Preimage[x] = privateKey.ZeroPre[x]
		}
	}
	return msg, sig, nil

}

// hint:
// arr[i/8]>>(7-(i%8)))&0x01
