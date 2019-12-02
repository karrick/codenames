package main // import "github.com/karrick/codenames"

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/karrick/gohm/v2"
	"github.com/karrick/golf"
	"github.com/karrick/gologs"
	"github.com/natefinch/lumberjack"
)

func fatal(err error) {
	log.Error("%s", err)
	os.Exit(1)
}

func usage(f string, args ...interface{}) {
	log.Error(f, args...)
	golf.Usage()
	os.Exit(2)
}

func init() {
	// Rather than display the entire usage information for a parsing error,
	// merely allow golf library to display the error message, then print the
	// command the user may use to show command line usage information.
	golf.Usage = func() { log.Error("Use '--help' for more information.") }
}

var (
	log *gologs.Logger

	optHelp    = golf.BoolP('h', "help", false, "Print command line help and exit")
	optDebug   = golf.Bool("debug", false, "Print debug output to stderr")
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

Command line options:
`)
		golf.PrintDefaultsTo(os.Stdout)
		return
	}

	var logOutput io.Writer = os.Stderr

	if *optLogs != "" {
		logOutput = &lumberjack.Logger{
			Filename:   *optLogs,
			MaxAge:     3,   // days
			MaxBackups: 10,  // count
			MaxSize:    100, // megabytes
		}
	}

	// Initialize the global log variable, which will be used very much like the
	// log standard library would be used.
	var err error
	log, err = gologs.New(logOutput, gologs.DefaultServiceFormat)
	if err != nil {
		panic(err)
	}

	// Configure log level according to command line flags.
	if *optDebug {
		log.SetDebug()
	} else if *optVerbose {
		log.SetVerbose()
	} else if *optQuiet {
		log.SetError()
	} else {
		log.SetInfo()
	}

	if *optAdjectives == "" || *optAnimals == "" {
		usage("must specify file for both adjectives and animals")
	}

	if *optCert == "" || *optKey == "" {
		if *optRedirect {
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
			clearSrv.Handler = http.HandlerFunc(makeHttpRedirector(fmt.Sprintf(":%d", *optHttps)))
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

	sigLog := gologs.NewBranchWithPrefix(log, "[SIGNAL] ")
	sigLog.Info("entering loop")

	prev := time.Now()
	for {
		select {
		case now := <-time.After(10 * time.Second):
			queries := atomic.SwapUint64(&total, 0)
			duration := now.Sub(prev)
			rate := float64(queries*uint64(time.Second)) / float64(duration)
			sigLog.Info("%d queries in %s; %g qps", queries, duration, rate)
			prev = now
		case sig := <-signals:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				sigLog.Info("received %s", sig)
				clearSrv.Shutdown(context.Background())
				if cipher {
					cipherSrv.Shutdown(context.Background())
				}
				sigLog.Info("shutdown complete; exiting")
				os.Exit(0)
			case syscall.SIGUSR1:
				if atomic.LoadUint32(&globalLogBitmask) == gohm.LogStatusErrors {
					sigLog.Info("received %s; toggling request logging to log all requests", sig)
					atomic.StoreUint32(&globalLogBitmask, gohm.LogStatusAll)
				} else {
					sigLog.Info("received %s; toggling request logging to log error requests", sig)
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
