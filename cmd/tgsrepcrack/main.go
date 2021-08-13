package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/violenttestpen/kerberoast.go/kerberos"
)

const bufSize = 10000
const charNewline = '\n'

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
		failOnError(err)
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
	wordlist, err := loadWordlist(ctx, wordlistfile)
	failOnError(err)

	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func() {
			defer wg.Done()
			for word := range wordlist {
				select {
				case <-ctx.Done():
					return
				default:
					hash, err := kerberos.NTLMHash(word)
					if err != nil {
						fmt.Println(err)
						cancel()
						return
					}

					ticketMutex.RLock()
					tickets := encTickets[:]
					ticketMutex.RUnlock()

					for i := range tickets[:] {
						kdata, _, err := kerberos.Decrypt(hash, 2, tickets[i].et)
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

func loadWordlist(ctx context.Context, wordlistfile string) (<-chan *string, error) {
	ch := make(chan *string, bufSize)
	wordlist, err := os.Open(wordlistfile)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(ch)
		defer wordlist.Close()

		if lazyLoad {
			reader := bufio.NewScanner(wordlist)
			for reader.Scan() {
				select {
				case <-ctx.Done():
					return
				default:
					word := reader.Text()
					ch <- &word
				}
			}
		} else {
			stat, _ := os.Stat(wordlist.Name())
			data := make([]byte, stat.Size())
			wordlist.Read(data)

			i := bytes.IndexByte(data, charNewline)
			for i != -1 {
				select {
				case <-ctx.Done():
					return
				default:
					word := string(data[:i])
					ch <- &word
					data = data[i+1:]
					i = bytes.IndexByte(data, charNewline)
				}
			}
			if len(data) > 0 {
				word := string(data)
				ch <- &word
			}
		}
	}()
	return ch, nil
}

func failOnError(err error) {
	if err != nil {
		panic(err)
	}
}
