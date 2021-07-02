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

	"github.com/hashicorp/go-uuid"
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
	flag.StringVar(&wordlistfile, "w", "", "The wordlist to use")
	flag.StringVar(&fileString, "f", "", "A comma separated list of filepaths to Kerberos tickets in kirbi format")
	flag.UintVar(&workers, "t", uint(runtime.NumCPU()), "Number of worker threads")
	flag.BoolVar(&benchmark, "b", false, "Benchmark mode")
	flag.BoolVar(&lazyLoad, "-lazy", false, "Enable lazy loading of wordlist for low memory systems")
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

	if benchmark {
		benchmarkMode(encTickets)
		return
	}

	if len(encTickets) > 0 {
		fmt.Println("Cracking", len(encTickets), "tickets...")
	} else {
		fmt.Println("No tickets found")
		return
	}

	startTime := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	wordlist, err := loadWordlist(ctx, wordlistfile)
	failOnError(err)

	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func(ctx context.Context, wordlist <-chan string) {
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
					tickets := encTickets
					ticketMutex.RUnlock()

					for _, ticket := range tickets {
						kdata, _, err := kerberos.Decrypt(hash, 2, ticket.et)
						if err != nil && err != kerberos.ErrChecksum {
							fmt.Println(err)
							cancel()
							return
						}

						if kdata != nil {
							ticketMutex.Lock()
							encTickets = append(encTickets[:ticket.i], encTickets[ticket.i+1:]...)
							ticketMutex.Unlock()

							fmt.Printf("found password for ticket %d: %s  File: %s\n", ticket.i, word, ticket.filename)
							if len(encTickets) == 0 {
								fmt.Println("Successfully cracked all tickets")
								cancel()
								return
							}
						}
					}
				}
			}
		}(ctx, wordlist)
	}
	wg.Wait()

	if len(encTickets) > 0 {
		fmt.Println("Unable to crack", len(encTickets), "tickets")
	}

	fmt.Println("Completed in", time.Since(startTime))
}

func loadWordlist(ctx context.Context, wordlistfile string) (<-chan string, error) {
	ch := make(chan string, bufSize)
	wordlist, err := os.Open(wordlistfile)
	if err != nil {
		return nil, err
	}

	go func(ctx context.Context) {
		defer close(ch)
		defer wordlist.Close()

		if lazyLoad {
			reader := bufio.NewScanner(wordlist)
			for reader.Scan() {
				select {
				case <-ctx.Done():
					return
				default:
					ch <- reader.Text()
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
					ch <- string(data[:i])
					data = data[i+1:]
					i = bytes.IndexByte(data, charNewline)
				}
			}
			if len(data) > 0 {
				ch <- string(data)
			}
		}
	}(ctx)
	return ch, nil
}

func benchmarkMode(encTickets []ticketList) {
	const N = 30

	var keys [N]string
	for i := 0; i < N; i++ {
		keys[i], _ = uuid.GenerateUUID()
	}

	attemptsC := make(chan int64, workers)
	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func(i uint) {
			defer wg.Done()
			for _, ticket := range encTickets {
				var count int64
				var elapsed time.Duration
				for elapsed < 1*time.Second {
					count++
					startTime := time.Now()
					for i := 0; i < N; i++ {
						hash, _ := kerberos.NTLMHash(keys[i])
						kerberos.Decrypt(hash, 2, ticket.et)
					}
					elapsed += time.Since(startTime)
				}

				attemptsPerSec := N * count * int64(time.Second) / elapsed.Nanoseconds()
				fmt.Println("Core", i, ":", ticket.filename, ":", attemptsPerSec, "keys/s")
				attemptsC <- attemptsPerSec
			}
		}(i)
	}
	wg.Wait()

	var total int64
	for i := uint(0); i < workers; i++ {
		total += <-attemptsC
	}
	fmt.Println("Total:", total/int64(len(encTickets)), "keys/s")
}

func failOnError(err error) {
	if err != nil {
		panic(err)
	}
}
