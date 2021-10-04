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
	flag.StringVar(&hash, "h", "", "Hashcat compatible AS-REP hash")
	flag.UintVar(&workers, "t", uint(runtime.NumCPU()), "Number of worker threads")
	flag.BoolVar(&lazyLoad, "l", false, "Enable lazy loading of wordlist for low memory systems")
	flag.Parse()

	if hash == "" {
		fmt.Println("Missing AS-REP hash")
		flag.Usage()
		return
	}

	asrephash, err := extractASREPHash(hash)
	util.FailOnError(err)

	startTime := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	wordlist, err := util.LoadWordlist(ctx, wordlistfile, lazyLoad)
	util.FailOnError(err)

	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func() {
			defer wg.Done()
			k := kerberos.New()
			for word := range wordlist {
				select {
				case <-ctx.Done():
					return
				default:
					hash, err := k.NTLMHash(word)
					if err != nil {
						fmt.Println(err)
						cancel()
						return
					}

					// message type 8 for AS-REP instead of type 2
					kdata, _, err := k.Decrypt(hash, 8, asrephash)
					if err != nil && err != kerberos.ErrChecksum {
						fmt.Println(err)
						cancel()
						return
					}

					if kdata != nil {
						fmt.Printf("found password for AS-REP hash: %s\n", *word)
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
