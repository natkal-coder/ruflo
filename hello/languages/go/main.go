// Package main implements a comprehensive "Hello, World!" program in Go.
// This demonstrates idiomatic Go programming with various language features,
// error handling, concurrency, and best practices.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Greeter interface defines the contract for greeting behavior
type Greeter interface {
	Greet(name string) string
}

// SimpleGreeter implements a basic greeting
type SimpleGreeter struct {
	prefix string
}

// NewSimpleGreeter creates a new SimpleGreeter instance
func NewSimpleGreeter(prefix string) *SimpleGreeter {
	return &SimpleGreeter{prefix: prefix}
}

// Greet returns a greeting message
func (g *SimpleGreeter) Greet(name string) string {
	if name == "" {
		name = "World"
	}
	return fmt.Sprintf("%s, %s!", g.prefix, name)
}

// AsyncGreeter demonstrates concurrent greeting with channels
type AsyncGreeter struct {
	greeter Greeter
}

// NewAsyncGreeter creates a new AsyncGreeter
func NewAsyncGreeter(greeter Greeter) *AsyncGreeter {
	return &AsyncGreeter{greeter: greeter}
}

// GreetConcurrently greets multiple names concurrently
func (ag *AsyncGreeter) GreetConcurrently(names []string) []string {
	results := make([]string, len(names))
	var wg sync.WaitGroup
	
	for i, name := range names {
		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			// Simulate some work
			time.Sleep(100 * time.Millisecond)
			results[idx] = ag.greeter.Greet(n)
		}(i, name)
	}
	
	wg.Wait()
	return results
}

// GreetWithContext demonstrates context usage for cancellation
func GreetWithContext(ctx context.Context, name string, delay time.Duration) (string, error) {
	select {
	case <-time.After(delay):
		return fmt.Sprintf("Hello, %s! (after %v)", name, delay), nil
	case <-ctx.Done():
		return "", fmt.Errorf("greeting cancelled: %w", ctx.Err())
	}
}

// demonstrateFeatures shows various Go language features
func demonstrateFeatures() {
	fmt.Println("\n=== Go Language Features ===")
	
	// Slices and range
	languages := []string{"Go", "Rust", "Python", "JavaScript"}
	fmt.Println("\nLanguages:")
	for i, lang := range languages {
		fmt.Printf("%d. %s\n", i+1, lang)
	}
	
	// Maps
	versions := map[string]string{
		"Go":         "1.21",
		"Python":     "3.12",
		"JavaScript": "ES2024",
	}
	fmt.Println("\nVersions:")
	for lang, version := range versions {
		fmt.Printf("- %s: %s\n", lang, version)
	}
	
	// Structs and methods
	type Developer struct {
		Name      string
		Languages []string
	}
	
	dev := Developer{
		Name:      "Gopher",
		Languages: []string{"Go", "Python", "JavaScript"},
	}
	fmt.Printf("\nDeveloper: %s knows %s\n", dev.Name, strings.Join(dev.Languages, ", "))
	
	// Error handling
	if err := doSomething(); err != nil {
		log.Printf("Warning: %v", err)
	}
	
	// Defer demonstration
	func() {
		defer fmt.Println("Deferred: This prints last in the function")
		fmt.Println("This prints first")
	}()
}

// doSomething simulates a function that might return an error
func doSomething() error {
	// Simulate success for demo
	return nil
}

// main is the entry point of the program
func main() {
	// Command-line flags
	var (
		name      = flag.String("name", "", "Name to greet")
		async     = flag.Bool("async", false, "Use async greeting")
		showDemo  = flag.Bool("demo", false, "Show Go features demo")
		timeout   = flag.Duration("timeout", 2*time.Second, "Timeout for context example")
	)
	flag.Parse()
	
	fmt.Println("=== Go Hello World ===")
	
	// Basic greeting
	greeter := NewSimpleGreeter("Hello")
	fmt.Println(greeter.Greet(*name))
	
	// Interface polymorphism
	var g Greeter = greeter
	fmt.Println("Via interface:", g.Greet("Go Developer"))
	
	// Async greeting
	if *async {
		fmt.Println("\nAsync Greetings:")
		asyncGreeter := NewAsyncGreeter(greeter)
		names := []string{"Alice", "Bob", "Charlie", "Diana"}
		results := asyncGreeter.GreetConcurrently(names)
		for _, result := range results {
			fmt.Println(result)
		}
	}
	
	// Context example
	fmt.Println("\nContext Example:")
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	
	if greeting, err := GreetWithContext(ctx, "Context User", 500*time.Millisecond); err != nil {
		log.Printf("Context error: %v", err)
	} else {
		fmt.Println(greeting)
	}
	
	// Show demo if requested
	if *showDemo {
		demonstrateFeatures()
	}
	
	// Channel example
	fmt.Println("\nChannel Communication:")
	messages := make(chan string, 2)
	messages <- "Hello from channel 1"
	messages <- "Hello from channel 2"
	close(messages)
	
	for msg := range messages {
		fmt.Println(msg)
	}
	
	fmt.Println("\nProgram completed successfully!")
}