package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"runtime"
	"strings"
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
	chunkSize    int
)

func main() {
	flag.StringVar(&wordlistfile, "w", "", "Wordlist to use")
	flag.StringVar(&hash, "h", "", "Hashcat compatible AS-REP hash")
	flag.UintVar(&workers, "t", uint(runtime.NumCPU()), "Number of worker threads")
	flag.BoolVar(&lazyLoad, "l", false, "Enable lazy loading of wordlist for low memory systems")
	flag.IntVar(&chunkSize, "s", 32, "Chunk size")
	flag.Parse()

	if hash == "" {
		fmt.Println("Missing AS-REP hash")
		flag.Usage()
		return
	}

	asrephash, err := extractASREPHash(hash)
	util.FailOnError(err)

	ctx, cancel := context.WithCancel(context.Background())
	wordlist, err := util.LoadWordlist(ctx, wordlistfile, lazyLoad, chunkSize)
	util.FailOnError(err)

	startTime := time.Now()
	msgType := []byte{0x8, 0x0, 0x0, 0x0}
	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func() {
			defer wg.Done()
			k := kerberos.New()
			var hash [md4.Size]byte
			for words := range wordlist {
				select {
				case <-ctx.Done():
					return
				default:
					for _, word := range words {
						err := k.NTLMHash(word, hash[:])
						if err != nil {
							fmt.Println(err)
							cancel()
							return
						}

						// message type 8 for AS-REP instead of type 2
						kdata, _, err := k.Decrypt(hash[:], msgType, asrephash)
						if err != nil && err != kerberos.ErrChecksum {
							fmt.Println(err)
							cancel()
							return
						}

						if kdata != nil {
							fmt.Printf("found password for AS-REP hash: %s\n", word)
							cancel()
							return
						}
					}
				}
			}
		}()
	}
	wg.Wait()

	fmt.Println("Completed in", time.Since(startTime))
}

func extractASREPHash(hash string) ([]byte, error) {
	if strings.HasPrefix(hash, "$krb5asrep$23$") {
		parts := strings.Split(hash[14:], "$")
		if len(parts) == 2 {
			if i := strings.Index(parts[0], ":"); i != -1 {
				return hex.DecodeString(parts[0][i+1:] + parts[1])
			}
		}
	}

	return nil, errors.New("Invalid AS-REP hash")
}
