package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/violenttestpen/kerberoast.go/kerberos"
)

func benchmarkMode(encTickets []ticketList) {
	const N = 30

	var keys [N]string
	for i := 0; i < N; i++ {
		keys[i], _ = uuid.GenerateUUID()
	}

	attemptsC := make(chan int64, workers*uint(len(encTickets)))
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
						hash, _ := kerberos.NTLMHash(&keys[i])
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
	for i, length := uint(0), uint(len(attemptsC)); i < length; i++ {
		total += <-attemptsC
	}
	fmt.Println("Total:", total/int64(len(encTickets)), "keys/s")
}
