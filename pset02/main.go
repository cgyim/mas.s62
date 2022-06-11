package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// A hash is a sha256 hash, as in pset01
type Hash [32]byte

// ToString gives you a hex string of the hash
func (self Hash) ToString() string {
	return fmt.Sprintf("%x", self)
}

// Blocks are what make the chain in this pset; different than just a 32 byte array
// from last time.  Has a previous block hash, a name and a nonce.
type Block struct {
	PrevHash Hash
	Name     string
	Nonce    string
}

// ToString turns a block into an ascii string which can be sent over the
// network or printed to the screen.
func (self Block) ToString() string {
	return fmt.Sprintf("%x %s %s", self.PrevHash, self.Name, self.Nonce)
}

// Hash returns the sha256 hash of the block.  Hopefully starts with zeros!
func (self Block) Hash() Hash {
	return sha256.Sum256([]byte(self.ToString()))
}

// BlockFromString takes in a string and converts it to a block, if possible
func BlockFromString(s string) (Block, error) {
	var bl Block

	// check string length
	if len(s) < 66 || len(s) > 100 {
		return bl, fmt.Errorf("Invalid string length %d, expect 66 to 100", len(s))
	}
	// split into 3 substrings via spaces
	subStrings := strings.Split(s, " ")

	if len(subStrings) != 3 {
		return bl, fmt.Errorf("got %d elements, expect 3", len(subStrings))
	}

	hashbytes, err := hex.DecodeString(subStrings[0])
	if err != nil {
		return bl, err
	}
	if len(hashbytes) != 32 {
		return bl, fmt.Errorf("got %d byte hash, expect 32", len(hashbytes))
	}

	copy(bl.PrevHash[:], hashbytes)

	bl.Name = subStrings[1]

	// remove trailing newline if there; the blocks don't include newlines, but
	// when transmitted over TCP there's a newline to signal end of block
	bl.Nonce = strings.TrimSpace(subStrings[2])

	// TODO add more checks on name/nonce ...?

	return bl, nil
}

func main() {

	fmt.Printf("NameChain Miner v0.1\n")

	ticker := time.NewTicker(5 * time.Minute)
	remine := make(chan *Block)
	defer close(remine)
	var tip Block
	go func() {
	PollTip:
		for {
			select {
			case <-ticker.C:
				runtime.GC()
				_latestTip, err := GetTipFromServer()
				if err != nil {
					fmt.Println(err)
					continue PollTip
				}

				if bytes.Equal(tip.PrevHash[:], _latestTip.PrevHash[:]) && tip.Nonce != "" {
					fmt.Printf("tip not changed, prev hash: [%s]\n", tip.PrevHash.ToString())
					continue PollTip
				} else {
					remine <- &_latestTip
					tip = _latestTip
				}
			}
		}
	}()

	var lastMiningCtx context.Context = nil
	var cancelLastMining context.CancelFunc = nil
	getBlock := make(chan *Block)
	defer close(getBlock)
MineLoop:
	for {
		fmt.Println("waiting for signals...")
		select {
		case newTip := <-remine:
			ctx, cancel := context.WithCancel(context.Background())
			bl := &Block{PrevHash: newTip.Hash(), Name: "zhejyan@microsoft.com"}
			if lastMiningCtx == nil {
				fmt.Printf("start remining ..\n")
			} else {
				fmt.Println("detect tip update, cancel last round and remine.")
				cancelLastMining()
			}
			lastMiningCtx = ctx
			cancelLastMining = cancel
			bl.Mine(ctx, uint8(33), getBlock)
		case blk := <-getBlock:
			fmt.Printf("SUCCESSFULLY mined a block! Sending to server.. PrevHash : [%s], name: [%s], nonce: [%s]\n", blk.PrevHash.ToString(), blk.Name, blk.Nonce)
			msg, err := SendBlockToServer(*blk)
			if strings.Contains(msg, "Block accepted") {
				fmt.Printf("SUCCESSFULLY submit a block! PrevHash : [%s], name: [%s], nonce: [%s]\n", blk.PrevHash.ToString(), blk.Name, blk.Nonce)
				break MineLoop
			} else {
				fmt.Println(msg, err)
			}
		}
	}
	// Basic idea:
	// Get tip from server, mine a block pointing to that tip,
	// then submit to server.
	// To reduce stales, poll the server every so often and update the
	// tip you're mining off of if it has changed.

	return
}
