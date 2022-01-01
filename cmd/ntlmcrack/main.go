package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/violenttestpen/kerberoast.go/pkg/kerberos"
	"github.com/violenttestpen/kerberoast.go/pkg/util"
	"golang.org/x/crypto/md4"
)

var (
	fileString   string
	hash         string
	wordlistfile string
	workers      uint
	benchmark    bool
	lazyLoad     bool
)

func main() {
	flag.StringVar(&wordlistfile, "w", "", "Wordlist to use")
	flag.StringVar(&hash, "h", "", "NTLM hash")
	flag.UintVar(&workers, "t", uint(runtime.NumCPU()), "Number of worker threads")
	flag.BoolVar(&lazyLoad, "l", false, "Enable lazy loading of wordlist for low memory systems")
	flag.Parse()

	if hash == "" {
		fmt.Println("Missing NTLM hash")
		flag.Usage()
		return
	}

	hashBytes, err := hex.DecodeString(hash)
	util.FailOnError(err)

	ctx, cancel := context.WithCancel(context.Background())
	wordlist, err := util.LoadWordlist(ctx, wordlistfile, lazyLoad)
	util.FailOnError(err)

	startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func() {
			defer wg.Done()
			k := kerberos.New()
			var hash [md4.Size]byte
			for word := range wordlist {
				select {
				case <-ctx.Done():
					return
				default:
					err := k.NTLMHash(word, hash[:])
					if err != nil {
						fmt.Println(err)
						cancel()
						return
					}

					if bytes.Equal(hash[:], hashBytes) {
						fmt.Printf("found password for NTLM hash: %s\n", *word)
						cancel()
						return
					}
				}
			}
		}()
	}
	wg.Wait()

	fmt.Println("Completed in", time.Since(startTime))
}
