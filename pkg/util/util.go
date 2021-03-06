package util

import (
	"bufio"
	"bytes"
	"context"
	"os"
)

const bufSize = 10000
const charNewline = '\n'

// LoadWordlist returns a stream of words from a file
func LoadWordlist(ctx context.Context, wordlistfile string, lazyLoad bool, chunkSize int) (<-chan []string, error) {
	ch := make(chan []string, bufSize)
	wordlist, err := os.Open(wordlistfile)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(ch)
		defer wordlist.Close()

		var buf []string
		if lazyLoad {
			reader := bufio.NewScanner(wordlist)
			for reader.Scan() {
				select {
				case <-ctx.Done():
					return
				default:
					if buf == nil {
						buf = make([]string, 0, chunkSize)
					}

					word := reader.Text()
					buf = append(buf, word)
					if len(buf) == chunkSize {
						ch <- buf
						buf = nil
					}
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
					if buf == nil {
						buf = make([]string, 0, chunkSize)
					}

					word := string(data[:i])
					buf = append(buf, word)

					if len(buf) == chunkSize {
						ch <- buf
						buf = nil
					}

					data = data[i+1:]
					i = bytes.IndexByte(data, charNewline)
				}
			}
			if len(data) > 0 {
				word := string(data)
				buf = append(buf, word)
			}
		}

		if buf != nil {
			ch <- buf
		}
	}()
	return ch, nil
}

// FailOnError panics when provided with a non-nil error
func FailOnError(err error) {
	if err != nil {
		panic(err)
	}
}
