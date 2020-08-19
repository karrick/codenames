# codenames

generate pseudo random codenames

Reads ajectives and animals from specified files and on each query returns a
concatenation from a random choice of one adjective followed by one animal.

## Building the program

```Bash
go build
```

## Using the program

SUMMARY: codenames [options] --adjectives FILE --animals FILE [options]

USAGE: Not all options may be used with all other options. See below synopsis
for reference.

NOTE: The --certfile and --keyfile must both be provided to serve HTTPS. When
serving HTTPS, the --redirect command line option causes HTTP traffic to be
redirected to HTTPS port.

SYNOPSIS:

    codenames [--debug | --verbose | --quiet]
              [--http NUMBER]
              [--logs FILE]
              [--certfile FILE] [--keyfile FILE] [--https NUMBER] [--redirect]
              --adjectives FILE --animals FILE

EXAMPLES:

    codenames --adjectives adjectives.txt --animals animals.txt
    codenames --adjectives adjectives.txt --animals animals.txt --http 80
    codenames --adjectives adjectives.txt --animals animals.txt --certfile $HOME/.local/share/mkcert/rootCA.pem --keyfile $HOME/.local/share/mkcert/rootCA-key.pem
    codenames --adjectives adjectives.txt --animals animals.txt --http 80 --https 443 --certfile $HOME/.local/share/mkcert/rootCA.pem --keyfile $HOME/.local/share/mkcert/rootCA-key.pem --redirect
