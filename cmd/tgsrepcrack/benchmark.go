package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/violenttestpen/kerberoast.go/pkg/kerberos"
	"golang.org/x/crypto/md4"
)

func benchmarkMode(encTickets []ticketList) {
	const N = 30

	var keys [N]string
	for i := 0; i < N; i++ {
		keys[i], _ = uuid.GenerateUUID()
	}

	var total int64

	var wg sync.WaitGroup
	wg.Add(int(workers))
	for i := uint(0); i < workers; i++ {
		go func(i uint) {
			defer wg.Done()
			k := kerberos.New()
			var hash [md4.Size]byte
			for _, ticket := range encTickets {
				var count int64
				var elapsed time.Duration

				for elapsed < 1*time.Second {
					count++
					startTime := time.Now()
					for i := 0; i < N; i++ {
						_ = k.NTLMHash(&keys[i], hash[:])
						k.Decrypt(hash[:], 2, ticket.et)
					}
					elapsed += time.Since(startTime)
				}

				attemptsPerSec := N * count * int64(time.Second) / elapsed.Nanoseconds()
				fmt.Println("Core", i, ":", ticket.filename, ":", attemptsPerSec, "keys/s")
				atomic.AddInt64(&total, attemptsPerSec)
			}
		}(i)
	}
	wg.Wait()

	fmt.Println("Total:", total/int64(len(encTickets)), "keys/s")
}
