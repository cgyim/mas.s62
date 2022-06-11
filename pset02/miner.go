package main

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"sync"
)

// This file is for the mining code.
// Note that "targetBits" for this assignment, at least initially, is 33.
// This could change during the assignment duration!  I will post if it does.

// Mine mines a block by varying the nonce until the hash has targetBits 0s in
// the beginning.  Could take forever if targetBits is too high.
// Modifies a block in place by using a pointer receiver.
func (self *Block) Mine(ctx context.Context, targetBits uint8, GetBlock chan *Block) {
	// your mining code here
	// also feel free to get rid of this method entirely if you want to
	// organize things a different way; this is just a suggestion
	complete := make(chan *Block)
	var wg sync.WaitGroup
	var once sync.Once
	wg.Add(runtime.NumCPU())
	ctxCancel, cancel := context.WithCancel(ctx)
	defer func() {
		go func() {
			fmt.Println("waiting for the current block mining exit...")
			select {
			case mined := <-complete:
				self.Nonce = mined.Nonce
				GetBlock <- self
			case <-ctx.Done():
			}
			cancel()
			wg.Wait()
		}()
	}()

	for mineWorkerId := 0; mineWorkerId < runtime.NumCPU(); mineWorkerId++ {
		_bl := &Block{
			PrevHash: self.PrevHash,
			Name:     self.Name}
		go func(_ctx context.Context, taskId int, bl *Block) {
		TryNextNonce:
			for nonce := uint64(taskId); ; nonce += uint64(runtime.NumCPU()) {
				select {
				case <-_ctx.Done():
					fmt.Printf("mining process TaskId: [%d] for current block cancelled.\n", taskId)
					wg.Done()
					return
				default:
				}
				bl.Nonce = strconv.FormatUint(nonce, 10)
				h := bl.Hash()
				//fmt.Printf("TaskId: [%d], nonce: [%d], hash : [%s]\n", taskId, nonce, h.ToString())
				for i := uint8(0); i < targetBits; i++ {
					// for every bit from the MSB down, check if it's a 1.
					// If it is, stop and fail.
					// Could definitely speed this up by checking bytes at a time.
					// Left as excercise for the reader...?
					if (h[i/8]>>(7-(i%8)))&0x01 == 1 {
						continue TryNextNonce
					}
				}
				fmt.Printf("TaskId: [%d], nonce: [%d], hash : [%s], current block mining success..\n", taskId, nonce, h.ToString())
				once.Do(func() {
					complete <- _bl
					close(complete)
				})
				wg.Done()
				return
			}
		}(ctxCancel, mineWorkerId, _bl)
	}
	return
}
