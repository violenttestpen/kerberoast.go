# Kerberoast.go

## Preamble

I was practicing some lab exercises on Active Directory for OSCP when I felt frustrated getting kirbi2john to play nice with John the Ripper. Hashcat didn't recognise the ticket either, and tgsrepcrack.py took forever to crack even a single ticket given its single-threaded nature. Hence, I've decided to reimplement common Kerberoast tools in Go in order to maximise my available CPU cores for a better multi-threaded hash cracking experience.

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
  -s int
        Chunk size (default 32)
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
  -s int
        Chunk size (default 32)
  -t uint
        Number of worker threads (default 4)
  -w string
        Wordlist to use
```

Example:

```
asrepcrack.exe -h $krb5asrep$23$SPN@domain.local:abcdef -w /path/to/wordlist [-t <num_of_worker_threads>] [-l]
```

### ntlmcrack

To install,

```
go install github.com/violenttestpen/kerberoast.go/cmd/ntlmcrack@latest
```

To use,

```
Usage of ntlmcrack:
  -h string
        NTLM hash
  -l    Enable lazy loading of wordlist for low memory systems
  -s int
        Chunk size (default 32)
  -t uint
        Number of worker threads (default 4)
  -w string
        Wordlist to use
```

Example:

```
ntlmcrack.exe -h $krb5asrep$23$SPN@domain.local:abcdef -w /path/to/wordlist [-t <num_of_worker_threads>] [-l]
```

## Acknowledgements

- [Kerberoast](https://github.com/nidem/kerberoast)
