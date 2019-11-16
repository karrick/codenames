package main // import "github.com/karrick/codenames"

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/karrick/gohm/v2"
	"github.com/karrick/golf"
	"github.com/natefinch/lumberjack"
)

// fatal prints the error to standard error then exits the program with status
// code 1.
func fatal(err error) {
	stderr("%s\n", err)
	os.Exit(1)
}

// newline returns a string with exactly one terminating newline character.
// More simple than strings.TrimRight.  When input string has multiple newline
// characters, it will strip off all but first one, reusing the same underlying
// string bytes.  When string does not end in a newline character, it returns
// the original string with a newline character appended.
func newline(s string) string {
	l := len(s)
	if l == 0 {
		return "\n"
	}

	// While this is O(length s), it stops as soon as it finds the first non
	// newline character in the string starting from the right hand side of the
	// input string.  Generally this only scans one or two characters and
	// returns.
	for i := l - 1; i >= 0; i-- {
		if s[i] != '\n' {
			if i+1 < l && s[i+1] == '\n' {
				return s[:i+2]
			}
			return s[:i+1] + "\n"
		}
	}

	return s[:1] // all newline characters, so just return the first one
}

// stderr formats and prints its arguments to standard error after prefixing
// them with the program name.
func stderr(f string, args ...interface{}) {
	os.Stderr.Write([]byte(ProgramName + ": " + newline(fmt.Sprintf(f, args...))))
}

// usage prints the error to standard error, prints message how to get help,
// then exits the program with status code 2.
func usage(f string, args ...interface{}) {
	stderr(f, args...)
	golf.Usage()
	os.Exit(2)
}

// verbose formats and prints its arguments to standard error after prefixing
// them with the program name.  This skips printing when optVerbose is false.
func verbose(f string, args ...interface{}) {
	if *optVerbose {
		stderr(f, args...)
	}
}

// warning formats and prints its arguments to standard error after prefixing
// them with the program name.  This skips printing when optQuiet is true.
func warning(f string, args ...interface{}) {
	if !*optQuiet {
		stderr(f, args...)
	}
}

var ProgramName string

func init() {
	var err error
	if ProgramName, err = os.Executable(); err != nil {
		ProgramName = os.Args[0]
	}
	ProgramName = filepath.Base(ProgramName)

	// Rather than display the entire usage information for a parsing error,
	// merely allow golf library to display the error message, then print the
	// command the user may use to show command line usage information.
	golf.Usage = func() {
		stderr("Use `%s --help` for more information.\n", ProgramName)
	}
}

var (
	optHelp    = golf.BoolP('h', "help", false, "Print command line help and exit")
	optQuiet   = golf.BoolP('q', "quiet", false, "Do not print intermediate errors to stderr")
	optVerbose = golf.BoolP('v', "verbose", false, "Print verbose output to stderr")

	optCert = golf.String("certfile", "", "specify option location for TLS cert file")
	optKey  = golf.String("keyfile", "", "specify option location for TLS key file")

	optAdjectives = golf.String("adjectives", "", "specify file with adjectives")
	optAnimals    = golf.String("animals", "", "specify file with animals")
	optLogs       = golf.String("logs", "", "specify optional service log file")
	optHttp       = golf.Int("http", 8080, "specify http port")
	optHttps      = golf.Int("https", 8443, "specify https port")
	optRedirect   = golf.Bool("redirect", false, "redirect HTTP to HTTPS")
)

func main() {
	if *optLogs != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   *optLogs,
			MaxAge:     3,   // days
			MaxBackups: 10,  // count
			MaxSize:    100, // megabytes
		})
	}

	golf.Parse()

	if *optHelp {
		// Show detailed help then exit, ignoring other possibly conflicting
		// options when '--help' is given.
		fmt.Printf(`codenames microservice

Reads ajectives and animals from specified files and on each query returns a
concatenation from a random choice of one adjective followed by one animal.

SUMMARY: codenames [options] --adjectives FILE --animals FILE [options]

USAGE: Not all options may be used with all other options. See below synopsis
for reference.

NOTE: The --certfile and --keyfile must both be provided to serve HTTPS. When
serving HTTPS, the --redirect command line option causes HTTP traffic to be
redirected to HTTPS port.

SYNOPSIS:

    codenames [--quiet | [--force | --verbose]]
              [--http NUMBER]
              [--logs FILE]
              [--certfile FILE] [--keyfile FILE] [--https NUMBER] [--redirect]
              --adjectives FILE --animals FILE

EXAMPLES:

    codenames --adjectives adjectives.txt --animals animals.txt
    codenames --adjectives adjectives.txt --animals animals.txt --http 80
    codenames --adjectives adjectives.txt --animals animals.txt --certfile $HOME/.local/share/mkcert/rootCA.pem --keyfile $HOME/.local/share/mkcert/rootCA-key.pem
    codenames --adjectives adjectives.txt --animals animals.txt --http 80 --https 443 --certfile $HOME/.local/share/mkcert/rootCA.pem --keyfile $HOME/.local/share/mkcert/rootCA-key.pem --redirect

Command line options:
`)
		golf.PrintDefaultsTo(os.Stdout)
		return
	}

	if *optAdjectives == "" || *optAnimals == "" {
		usage("must specify file for both adjectives and animals")
	}

	if *optCert == "" || *optKey == "" {
		if !*optRedirect {
			usage("cannot redirect HTTP to HTTPS without HTTPS, and cannot serve HTTPS with cert file ane key file")
		}
		if *optHttps != 8443 {
			usage("cannot redirect HTTP to HTTPS without HTTPS, and cannot serve HTTPS with cert file ane key file")
		}
	}

	adjectives, err := loadFromFile(*optAdjectives)
	if err != nil {
		fatal(err)
	}

	animals, err := loadFromFile(*optAnimals)
	if err != nil {
		fatal(err)
	}

	var globalLogBitmask = gohm.LogStatusAll
	var total uint64

	accessLogs := &lumberjack.Logger{
		Filename:   "access.log",
		MaxAge:     30,  // days
		MaxBackups: 50,  // count
		MaxSize:    500, // megabytes
	}

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tuple := adjectives[rand.Intn(len(adjectives))] + " " + animals[rand.Intn(len(animals))] + "\n"
		w.Write([]byte(tuple))
		atomic.AddUint64(&total, 1)
	})

	h = gohm.New(h, gohm.Config{
		LogBitmask: &globalLogBitmask,
		LogWriter:  accessLogs,
	})

	clearSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *optHttp),
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		IdleTimeout:  3 * time.Second,
		Handler:      h,
	}

	tlsConfig := &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	cipherSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *optHttps),
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		IdleTimeout:  3 * time.Second,
		TLSConfig:    tlsConfig,
		Handler:      h,
	}

	var cipher bool

	if *optCert != "" && *optKey != "" {
		cipher = true

		if *optRedirect {
			clearSrv.Handler = http.HandlerFunc(makeHttpRedirector(":8443"))
		}

		go func() {
			err := cipherSrv.ListenAndServeTLS(*optCert, *optKey)
			if err != nil && err != http.ErrServerClosed {
				fatal(err)
			}
		}()
	}

	go func() {
		err := clearSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			fatal(err)
		}
	}()

	signals := make(chan os.Signal, 2) // buffered channel
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	log.Printf("[SIGNAL] entering loop\n")

	prev := time.Now()
	for {
		select {
		case now := <-time.After(10 * time.Second):
			queries := atomic.SwapUint64(&total, 0)
			duration := now.Sub(prev)
			rate := float64(queries*uint64(time.Second)) / float64(duration)
			log.Printf("%d queries in %s; %g qps\n", queries, duration, rate)
			prev = now
		case sig := <-signals:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("[SIGNAL] received %s\n", sig)
				clearSrv.Shutdown(context.Background())
				if cipher {
					cipherSrv.Shutdown(context.Background())
				}
				log.Printf("[SIGNAL] shutdown complete; exiting\n")
				os.Exit(0)
			case syscall.SIGUSR1:
				if atomic.LoadUint32(&globalLogBitmask) == gohm.LogStatusErrors {
					log.Printf("[SIGNAL] received %s; toggling request logging to log all requests\n", sig)
					atomic.StoreUint32(&globalLogBitmask, gohm.LogStatusAll)
				} else {
					log.Printf("[SIGNAL] received %s; toggling request logging to log error requests\n", sig)
					atomic.StoreUint32(&globalLogBitmask, gohm.LogStatusErrors)
				}
			}
		}
	}
}

func loadFromFile(pathname string) ([]string, error) {
	var list []string
	fh, err := os.Open(pathname)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(fh)
	for s.Scan() {
		list = append(list, s.Text())
	}
	cerr := fh.Close()
	if err := s.Err(); err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	return list, nil
}

func makeHttpRedirector(cipherPort string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var url string
		if index := strings.IndexRune(r.Host, ':'); index >= 0 {
			url = "https://" + r.Host[:index] + cipherPort + r.URL.String()
		} else {
			url = "https://" + r.Host + cipherPort + r.URL.String()
		}
		http.Redirect(w, r, url, http.StatusMovedPermanently)
	})
}
