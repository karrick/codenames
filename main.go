package main // import "github.com/karrick/codenames"

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/karrick/gohm"
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

var (
	optHelp    = golf.BoolP('h', "help", false, "Print command line help and exit")
	optQuiet   = golf.BoolP('q', "quiet", false, "Do not print intermediate errors to stderr")
	optVerbose = golf.BoolP('v', "verbose", false, "Print verbose output to stderr")

	optAdjectives = golf.String("adjectives", "", "specify file with adjectives")
	optAnimals    = golf.String("animals", "", "specify file with animals")
	optLogs       = golf.String("logs", "", "specify optional service log file")
	optPort       = golf.Int("port", 8080, "specify http port")
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
		fmt.Printf(`codenames

Reads ajectives and animals from specified files and on each query returns a
concatenation from a random choice of one adjective followed by one animal.

SUMMARY:  codenames [options] [file1 [file2 ...]] [options]

USAGE: Not all options  may be used with all other  options. See below synopsis
for reference.

    codenames [--quiet | [--force | --verbose]]
              --adjectives FILE
              --animals FILE
              [--port NUMBER]

EXAMPLES:

    codenames --adjectives adjectives.txt --animals animals.txt
    codenames --adjectives adjectives.txt --animals animals.txt --port 8080

Command line options:
`)
		golf.PrintDefaults() // frustratingly, this only prints to stderr, and cannot change because it mimicks flag stdlib package
		return
	}

	if *optAdjectives == "" || *optAnimals == "" {
		usage("must specify file for both adjectives and animals")
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

	go func() {
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			tuple := adjectives[rand.Intn(len(adjectives))] + " " + animals[rand.Intn(len(animals))] + "\n"
			w.Write([]byte(tuple))
			atomic.AddUint64(&total, 1)
		})

		config := gohm.Config{
			LogBitmask: &globalLogBitmask,
			LogFormat:  "{client-ip} {http-Client_ip} [{begin-iso8601}] \"{method} {uri} {proto}\" {status} {bytes} {duration} {error}",
			LogWriter:  accessLogs,
		}

		err := http.ListenAndServe(fmt.Sprintf(":%d", *optPort), gohm.New(h, config))
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
