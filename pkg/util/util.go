package util

import (
	"bufio"
	"context"
	"os"
)

const bufSize = 10000
const charNewline = '\n'

// LoadWordlist returns a stream of words from a file
func LoadWordlist(ctx context.Context, wordlistfile string, chunkSize int) (<-chan []string, error) {
	ch := make(chan []string, bufSize)
	wordlist, err := os.Open(wordlistfile)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(ch)
		defer wordlist.Close()

		buf := make([]string, 0, chunkSize)
		reader := bufio.NewScanner(wordlist)
		for reader.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				if buf == nil {
					buf = make([]string, 0, chunkSize)
				}

				buf = append(buf, reader.Text())
				if len(buf) == chunkSize {
					ch <- buf
					buf = nil
				}
			}
		}
		ch <- buf
	}()
	return ch, nil
}

// FailOnError panics when provided with a non-nil error
func FailOnError(err error) {
	if err != nil {
		panic(err)
	}
}
