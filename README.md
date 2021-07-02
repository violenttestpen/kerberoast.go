# Kerberoast.go

## Preamble

I was practicing some lab exercises on Active Directory when I felt frustrated getting kirbi2john to play nice with my local John the Ripper. To add salt to injury, Hashcat didn't recognise the ticket either, and tgsrepcrack.py took forever to crack a single ticket given its single-threaded nature. This is unacceptable in a time sensitive scenario such as during CTFs and red team engagements. Hence, I've spent a weekend implementing tgsrepcrack to Go in order to maximise my idle CPU cores for a much better multi-threaded hash cracking experience.

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
