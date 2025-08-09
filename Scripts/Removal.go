package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"
	"runtime"
)

// Function to read domains from a file
func readDomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, strings.TrimSpace(scanner.Text()))
	}

	return domains, scanner.Err()
}

// Function to write domains to a file
func writeDomainsToFile(domains []string, filePath string) error {
	return ioutil.WriteFile(filePath, []byte(strings.Join(domains, "\n")), 0644)
}

// Function to open a file chooser using Python
func openFileChooser() (string, error) {
	cmd := exec.Command("python", "-c", `
import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw()  # Hide the root window
file_path = filedialog.askopenfilename(title="Select a TXT file", filetypes=[("Text files", "*.txt")])
print(file_path)  # Output the selected file path
`)
	output, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		return "", fmt.Errorf("error executing file chooser: %v, output: %s", err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

// Worker function to process domains
func worker(jobs <-chan string, firstDomains map[string]struct{}, modifiedDomains chan<- string, foundDomains chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range jobs {
		if _, exists := firstDomains[domain]; exists {
			foundDomains <- domain
		} else {
			modifiedDomains <- domain
		}
	}
}

func main() {
	fmt.Println("Select the first TXT file containing domain names:")
	firstFilePath, err := openFileChooser()
	if err != nil || firstFilePath == "" {
		fmt.Println("Error selecting first file:", err)
		return
	}

	fmt.Println("Select the second TXT file containing domain names:")
	secondFilePath, err := openFileChooser()
	if err != nil || secondFilePath == "" {
		fmt.Println("Error selecting second file:", err)
		return
	}

	firstDomainsRaw, err := readDomainsFromFile(firstFilePath)
	if err != nil {
		fmt.Println("Error reading first file:", err)
		return
	}

	secondDomainsRaw, err := readDomainsFromFile(secondFilePath)
	if err != nil {
		fmt.Println("Error reading second file:", err)
		return
	}

	firstDomains := make(map[string]struct{})
	for _, domain := range firstDomainsRaw {
		firstDomains[domain] = struct{}{}
	}

	jobs := make(chan string, len(secondDomainsRaw))
	modifiedDomains := make(chan string, len(secondDomainsRaw)) // Buffered channel
	foundDomains := make(chan string, len(secondDomainsRaw))    // Buffered channel

	var wg sync.WaitGroup

	numWorkers := runtime.NumCPU() // Get number of CPU cores

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go worker(jobs, firstDomains, modifiedDomains, foundDomains, &wg)
	}

	go func() {
		wg.Wait()
		close(modifiedDomains)
		close(foundDomains) // Close foundDomains channel after all workers are done.
	}()

	for _, domain := range secondDomainsRaw {
		jobs <- domain
	}
	close(jobs)

	var modifiedList []string

	for modifiedDomain := range modifiedDomains {
		modifiedList = append(modifiedList, modifiedDomain)
	}

	var foundList []string

	for foundDomain := range foundDomains {
		foundList = append(foundList, foundDomain)
	}

	err = writeDomainsToFile(modifiedList, "modified.txt")
	if err != nil {
		fmt.Println("Error writing modified file:", err)
		return
	}

	err = writeDomainsToFile(foundList, "found_domains.txt") // Write found domains to a file.
	if err != nil {
		fmt.Println("Error writing found domains file:", err)
		return
	}

	fmt.Println("Complete.")
}
