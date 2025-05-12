/**
 * Author: Abner Benedito
 * Github: ghostkill73
 *
 * Usage:
 *	bsha256 -t <HASH> -f <WORDLIST> -w <WORKERS[default=runtime.NumCPU()]>
 *
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

////////////////////////////////////////////////////////////////////////////////////////////
// MAIN
////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	startTime := time.Now()

	// ----------------------------------------------------------------------
	// args
	// ----------------------------------------------------------------------

	arg := ParseArguments()

	// Format hash input to bytes
	targetHash, err := decodeTargetHash(arg.Hash)
	if err != nil {
		panic(err)
	}

	// Read wordlist
	file, err := os.Open(arg.FilePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// ----------------------------------------------------------------------
	// Brute-force
	// ----------------------------------------------------------------------

	// Defines password check interval and passwordChan buffer
	checkInterval, passwordBuffer := defIntervalAndBuffer(file)

	// Routines
	var wg sync.WaitGroup
	var found atomic.Bool
	passwordChan := make(chan []byte, passwordBuffer)
	resultChan := make(chan string, 1)

	for i := 0; i < arg.Workers; i++ {
		wg.Add(1)
		go bruteforce(
			targetHash,
			checkInterval,
			passwordChan,
			resultChan,
			&found,
			&wg,
		)
	}

	// Sending passwords to passwordChan
	go sendPasswords(
		file,
		passwordChan,
		&found,
	)

	// Wait routines
	go func(wg *sync.WaitGroup) {
		wg.Wait()
		close(resultChan)
	}(&wg)

	// Verify if the password has been found
	select {
	case result, ok := <-resultChan:
		if ok {
			fmt.Printf("Password found: %s\n", result)
			fmt.Println("Execution time:", time.Since(startTime))
			return
		}
	}
	fmt.Println("No matching password found.")
	fmt.Println("Execution time:", time.Since(startTime))
	return
}

////////////////////////////////////////////////////////////////////////////////////////////
// ARGUMENTS
////////////////////////////////////////////////////////////////////////////////////////////

type CmdArguments struct {
	Hash     string
	FilePath string
	Workers  int
}

// TODO: Add verify args
func ParseArguments() CmdArguments {
	var arg CmdArguments

	// -t
	flag.StringVar(&arg.Hash, "t", "", "Hash target")
	// -f
	flag.StringVar(&arg.FilePath, "f", "", "File path containing password list.")
	// -w
	flag.IntVar(&arg.Workers, "w", runtime.NumCPU(), "Number of worker goroutines to use.")

	flag.Parse()

	return arg
}

////////////////////////////////////////////////////////////////////////////////////////////
// UTILS
////////////////////////////////////////////////////////////////////////////////////////////

func bruteforce(
	target [32]byte,
	interval int,
	passwordChan <-chan []byte,
	resultChan chan<- string,
	found *atomic.Bool,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for j := 0; ; j++ {
		passwd, ok := <-passwordChan
		if !ok {
			return
		}
		if j%interval == 0 && found.Load() {
			return
		}

		hash := sha256.Sum256(passwd)
		if bytes.Equal(hash[:], target[:]) {
			found.Store(true)
			resultChan <- string(passwd)
			return
		}
	}
}

func sendPasswords(
	file *os.File,
	passwordChan chan<- []byte,
	found *atomic.Bool,
) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwd := scanner.Bytes()
		if len(passwd) > 0 && !found.Load() {
			passwordChan <- passwd
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	close(passwordChan)
}

// ----------------------------------------------------------------------

func decodeTargetHash(hash string) ([32]byte, error) {
	var result [32]byte

	decodedHash, err := hex.DecodeString(hash)
	if err != nil {
		return [32]byte{}, err
	}

	if len(decodedHash) != sha256.Size {
		return [32]byte{}, fmt.Errorf("Invalid hash format.")
	}

	copy(result[:], decodedHash)
	return result, nil
}

// ----------------------------------------------------------------------

func defIntervalAndBuffer(file *os.File) (int, int) {
	var interval int = 0
	var buffer int = 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lenLine := len(scanner.Text())
		if lenLine > buffer {
			buffer = lenLine
		}
		interval++
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	file.Seek(0, 0)
	return calcCheckInterval(interval), buffer
}

// ----------------------------------------------------------------------

type Threshold struct {
	maxLines int
	interval int
}

var checkThresholds = []Threshold{
	{100, 1},				// <=100 lines		-> every password
	{1000, 10},				// <=1,000 lines	-> every 10 passwords
	{100000, 100},			// <=100,000 lines	-> every 100 passwords
	{10000000, 1000},		// <=10M lines		-> every 1,000 passwords
}

func calcCheckInterval(lines int) int {
	for _, t := range checkThresholds {
		if lines <= t.maxLines {
			return t.interval
		}
	}
	return 10000 // Fallback
}
