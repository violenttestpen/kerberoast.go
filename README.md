# Kerberoast.go

## Preamble

I was practicing some lab exercises on Active Directory when I felt frustrated getting kirbi2john to play nice with my local John the Ripper. To add salt to injury, Hashcat didn't recognise the ticket either, and tgsrepcrack.py took forever to crack a single ticket given its single-threaded nature. Hence, I've decided to reimplement tgsrepcrack to Go in order to maximise my idle CPU cores for a much better multi-threaded hash cracking experience.

## Usage

### tgsrepcrack

To install,

```
go install github.com/violenttestpen/kerberoast.go/cmd/tgsrepcrack@latest
```

To use,

```
Usage of tgsrepcrack:
  -b    Benchmark mode
  -f string
        Comma-separated list of paths to Kerberos tickets in kirbi format
  -l    Enable lazy loading of wordlist for low memory systems
  -t uint
        Number of worker threads (default 4)
  -w string
        Wordlist to use
```

Example:

```
tgsrepcrack.exe -f /path/to/ticket -w /path/to/wordlist [-t <num_of_worker_threads>] [-l]
```

### asrepcrack

To install,

```
go install github.com/violenttestpen/kerberoast.go/cmd/asrepcrack@latest
```

To use,

```
Usage of asrepcrack:
  -h string
        Hashcat compatible AS-REP hash
  -l    Enable lazy loading of wordlist for low memory systems
  -t uint
        Number of worker threads (default 4)
  -w string
        Wordlist to use
```

Example:

```
asrepcrack.exe -h $krb5asrep$23$SPN@domain.local:abcdef -w /path/to/wordlist [-t <num_of_worker_threads>] [-l]
```

## Acknowledgements

- [Kerberoast](https://github.com/nidem/kerberoast)
