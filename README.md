# Kerberoast.go

## Preamble

I was practicing on some Active Directory lab exercises when I faced the frustration of getting kirbi2john playing nice with my local John the Ripper. Hashcat didn't recognise the ticket as well, while tgsrepcrack.py took forever to crack a single ticket owing to its single-threaded nature. Hence, I've implemented tgsrepcrack in Go to maximise my idle CPU cores for a multi-threaded cracking experience.

## Usage

### tgsrepcrack

To install,

```
go install github.com/violenttestpen/kerberoast.go/cmd/tgsrepcrack@latest
```

To use,

```
Usage of tgsrepcrack:
  --lazy
        Enable lazy loading of wordlist for low memory systems
  -b    Benchmark mode
  -f string
        A comma separated list of filepaths to Kerberos tickets in kirbi format
  -t uint
        Number of worker threads (default 4)
  -w string
        The wordlist to use
```

Example:

```
tgsrepcrack.exe -f /path/to/ticket -w /path/to/wordlist [-t <num_of_worker_threads>] [--lazy]
```

## Acknowledgements

- [Kerberoast](https://github.com/nidem/kerberoast)