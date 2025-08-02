package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"strconv"
	"syscall"
	"time"
)

var (
	mu               sync.Mutex
	logMu            sync.Mutex
	processed        int
	totalDomains     int
	startTime        time.Time
	statusFiles      = make(map[string]*os.File)
	mainFile         *os.File
	existingDomains  = make(map[string]bool)
	logFile          *os.File
	rateLogFile      *os.File
	workerMutex      sync.Mutex
	workerCancels    []context.CancelFunc
	workerCount      int
	expectedStatuses = map[string]bool{
		"NXDOMAIN":         true,
		"NOERROR":          true,
		"SERVFAIL":         true,
		"ITERATIVE_TIMEOUT": true,
		"ERROR":            true,
	}
	cpuCap        = 84.0
	minRate       = 130.0 // Minimum domains per second target
	cpuAtCapStart time.Time
	lowRateStart  time.Time
)

const (
	barWidth        = 50
	smoothingFactor = 0.2 // Exponential smoothing factor
	etaUpdatePeriod = 5 * time.Second
)

func getCPUUsage() (float64, error) {
	cmd := exec.Command("wmic", "cpu", "get", "loadpercentage")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected output: %s", string(output))
	}

	str := strings.TrimSpace(lines[1])
	percent, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, err
	}

	return percent, nil
}

func adjustWorkers(ctx context.Context, baseCtx context.Context, wg *sync.WaitGroup, domainsChan chan string) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	lastRate := 0.0
	lastCheck := time.Now()
	minRateConditionActive := true

	for {
		select {
		case <-ticker.C:
			cpuUsage, err := getCPUUsage()
			if err != nil {
				continue
			}

			workerMutex.Lock()
			current := workerCount
			newCount := current

			// Calculate current processing rate
			mu.Lock()
			currentProcessed := processed
			mu.Unlock()
			elapsed := time.Since(lastCheck).Seconds()
			currentRate := 0.0
			if elapsed > 0 {
				currentRate = float64(currentProcessed) / elapsed
			}

			// Track CPU at cap state
			now := time.Now()
			if cpuUsage >= cpuCap {
				if cpuAtCapStart.IsZero() {
					cpuAtCapStart = now
				}
			} else {
				cpuAtCapStart = time.Time{}
			}

			// Track low rate state
			if currentRate < minRate {
				if lowRateStart.IsZero() {
					lowRateStart = now
			}
			} else {
				lowRateStart = time.Time{}
			}

			// Disable min rate condition if CPU at cap for 8 seconds
			if !cpuAtCapStart.IsZero() && now.Sub(cpuAtCapStart) >= 2*time.Second {
				minRateConditionActive = false
				cpuAtCapStart = time.Time{} // Reset
			}

			// Re-enable min rate condition if rate below threshold for 2 seconds
			if !minRateConditionActive && !lowRateStart.IsZero() && now.Sub(lowRateStart) >= 1*time.Second {
				minRateConditionActive = true
				lowRateStart = time.Time{} // Reset
			}

			// Detect rate decay
			rateDecay := lastRate > 0 && currentRate < lastRate*0.9 // 10% drop

			// Aggressive scaling conditions
			scaleUp := false
			if cpuUsage < cpuCap-4 {
				scaleUp = true
			} else if cpuUsage < cpuCap && (rateDecay || (minRateConditionActive && currentRate < minRate)) {
				scaleUp = true
			}

			if scaleUp {
				// Scale up aggressively
				increase := max(1, current/2) // Increase by 50%
				if increase < 800 {
					increase = 800 // Minimum increase of 800 workers
				}
				newCount = current + increase
			} else if cpuUsage > cpuCap {
				// Scale down conservatively when over cap
				reduction := max(1, current/7) // Reduce by 5%
				newCount = current - reduction
				if newCount < 1 {
					newCount = 1
				}
			}

			if newCount != current {
				if newCount < current {
					// Scale down
					for i := 0; i < current-newCount; i++ {
						if len(workerCancels) > 0 {
							idx := len(workerCancels) - 1
							cancel := workerCancels[idx]
							workerCancels = workerCancels[:idx]
							cancel()
						}
					}
				} else {
					// Scale up
					for i := 0; i < newCount-current; i++ {
						workerCtx, cancel := context.WithCancel(baseCtx)
						workerCancels = append(workerCancels, cancel)
						wg.Add(1)
						go worker(workerCtx, wg, domainsChan)
					}
				}
				workerCount = newCount
			}

			// Update rate tracking
			lastRate = currentRate
			lastCheck = now
			workerMutex.Unlock()

		case <-ctx.Done():
			return
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func readDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || domain[0] == '#' || strings.ContainsAny(domain, " \t\r\n") {
			continue
		}
		if !existingDomains[domain] {
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

func loadExistingDomains() error {
	domainsFilePath := filepath.Join("bruh_output", "domains.txt")
	if _, err := os.Stat(domainsFilePath); os.IsNotExist(err) {
		return nil
	}

	file, err := os.Open(domainsFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			existingDomains[domain] = true
		}
	}

	dirs, err := os.ReadDir("bruh_output")
	if err != nil {
		return err
	}

	for _, dir := range dirs {
		if dir.IsDir() {
			statusFile := filepath.Join("bruh_output", dir.Name(), "domains.txt")
			if _, err := os.Stat(statusFile); err != nil {
				continue
			}

			file, err := os.Open(statusFile)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				domain := strings.TrimSpace(scanner.Text())
				if domain != "" {
					existingDomains[domain] = true
				}
			}
			file.Close()
		}
	}
	return nil
}

func parseStatus(output string) string {
	re := regexp.MustCompile(`status:\s*([A-Z]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func mapStatus(original string) string {
	switch original {
	case "FORMERR":
		return "NOERROR"
	case "AUTHFAIL", "NOTAUTH", "REFUSED":
		return "SERVFAIL"
	case "TIMEOUT":
		return "ITERATIVE_TIMEOUT"
	case "NOTZONE":
		return "NXDOMAIN"
	case "ERROR":
		return "ERROR"
	default:
		return original
	}
}

func runDnsLookupWithOutput(domain string) (string, string, error) {
	// Single continuous lookup with 30-minute timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dnslookup", domain)
	outputBytes, err := cmd.CombinedOutput()
	outputStr := string(outputBytes)

	if outputStr != "" {
		status := parseStatus(outputStr)
		return outputStr, status, err
	}
	return outputStr, "", err
}

// Check for blank output patterns
func isBlankOutput(output string) bool {
	trimmed := strings.TrimSpace(output)
	return trimmed == "dnslookup master" || trimmed == ""
}

func ensureStatusFile(status string) (*os.File, error) {
	mu.Lock()
	defer mu.Unlock()

	if f, exists := statusFiles[status]; exists {
		return f, nil
	}

	statusDir := filepath.Join("bruh_output", status)
	if err := os.MkdirAll(statusDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("error creating directory for status '%s': %w", status, err)
	}

	domainFilePath := filepath.Join(statusDir, "domains.txt")
	f, err := os.OpenFile(domainFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening file for status '%s': %w", status, err)
	}

	statusFiles[status] = f
	return f, nil
}

func writeDomain(domain, status string) error {
	mu.Lock()
	if existingDomains[domain] {
		mu.Unlock()
		return nil
	}
	existingDomains[domain] = true
	mu.Unlock()

	statusFile, err := ensureStatusFile(status)
	if err != nil {
		return fmt.Errorf("error getting status file: %w", err)
	}

	if _, err := statusFile.WriteString(domain + "\n"); err != nil {
		return fmt.Errorf("error writing to status file '%s': %w", status, err)
	}

	mu.Lock()
	defer mu.Unlock()
	if _, err := mainFile.WriteString(domain + "\n"); err != nil {
		return fmt.Errorf("error writing to main domains file: %w", err)
	}

	return nil
}

func worker(ctx context.Context, wg *sync.WaitGroup, domainsChan <-chan string) {
	defer wg.Done()
	for {
		select {
		case domain, ok := <-domainsChan:
			if !ok {
				return
			}
			processDomain(domain)
		case <-ctx.Done():
			return
		}
	}
}

func processDomain(domain string) {
	output, status, err := runDnsLookupWithOutput(domain)

	if isBlankOutput(output) {
		// Blank output - log but don't write to any file
		logMu.Lock()
		fmt.Fprintf(logFile, "[%s] Domain: %s\nOutput:\n%s\nVerdict: SKIPPED (blank output)\n%s\n\n",
			time.Now().Format(time.RFC3339), domain, output, strings.Repeat("-", 50))
		logMu.Unlock()

		mu.Lock()
		processed++
		mu.Unlock()
		return
	}

	if strings.Contains(output, "fatal] Cannot make the DNS request") && strings.Contains(output, "i/o timeout") {
		status = "TIMEOUT"
		mappedStatus := mapStatus(status)

		// Check if status is expected
		if !expectedStatuses[mappedStatus] {
			fmt.Fprintf(os.Stderr, "Unexpected status for domain %s: %s (original: %s)\n", domain, mappedStatus, status)
			mappedStatus = "ERROR"
		}

		logMu.Lock()
		fmt.Fprintf(logFile, "[%s] Domain: %s\nOutput:\n%s\nVerdict: TIMEOUT\n%s\n\n",
			time.Now().Format(time.RFC3339), domain, output, strings.Repeat("-", 50))
		logMu.Unlock()

		if err := writeDomain(domain, mappedStatus); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing domain %s: %v\n", domain, err)
		}

		mu.Lock()
		processed++
		mu.Unlock()
		return
	}

	if err != nil && status == "" {
		status = "ERROR"
	}

	if status == "" {
		status = "ERROR"
	}

	mappedStatus := mapStatus(status)

	// Check if status is expected
	if !expectedStatuses[mappedStatus] {
		fmt.Fprintf(os.Stderr, "Unexpected status for domain %s: %s (original: %s)\n", domain, mappedStatus, status)
		mappedStatus = "ERROR"
	}

	logMu.Lock()
	fmt.Fprintf(logFile, "[%s] Domain: %s\nOutput:\n%s\nVerdict: %s\n%s\n\n",
		time.Now().Format(time.RFC3339), domain, output, mappedStatus, strings.Repeat("-", 50))
	logMu.Unlock()

	if err := writeDomain(domain, mappedStatus); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing domain %s: %v\n", domain, err)
	}

	mu.Lock()
	processed++
	mu.Unlock()
}

func logRateStats() {
	ticker := time.NewTicker(500 * time.Millisecond) // Log every 500ms
	defer ticker.Stop()

	lastProcessed := 0
	lastTime := time.Now()

	for {
		select {
		case <-ticker.C:
			mu.Lock()
			current := processed
			mu.Unlock()

			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(current-lastProcessed) / elapsed
			}

			totalElapsed := now.Sub(startTime).Seconds()
			avgRate := 0.0
			if totalElapsed > 0 {
				avgRate = float64(current) / totalElapsed
			}

			workerMutex.Lock()
			wCount := workerCount
			workerMutex.Unlock()

			logMu.Lock()
			fmt.Fprintf(rateLogFile, "[%s] Workers: %d, Instant: %.2f/s, Avg: %.2f/s, Per Minute: %.2f\n",
				now.Format(time.RFC3339), wCount, rate, avgRate, rate*60)
			logMu.Unlock()

			lastProcessed = current
			lastTime = now
		}
	}
}

func getProcessTreeInfo() (pid int, name string, ancestors string) {
	pid = -1
	name = "unknown"
	ancestors = ""

	// Get parent PID
	ppid := os.Getppid()
	if ppid <= 0 {
		return
	}
	pid = ppid

	if runtime.GOOS == "windows" {
		// Try to get parent process name
		cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("processid=%d", pid), "get", "name")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(lines) >= 2 {
				name = strings.TrimSpace(lines[1])
			}
		}

		// Get process tree
		cmd = exec.Command("wmic", "process", "where", fmt.Sprintf("processid=%d", pid), "get", "parentprocessid,processid,name")
		output, err = cmd.Output()
		if err == nil {
			ancestors = strings.TrimSpace(string(output))
		}
	} else {
		// Unix-like systems
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		if _, err := os.Stat(exePath); err == nil {
			if link, err := os.Readlink(exePath); err == nil {
				name = filepath.Base(link)
			}
		}

		// Get process tree
		cmd := exec.Command("ps", "-f", "--ppid", fmt.Sprintf("%d", pid), "-o", "pid,ppid,comm")
		output, err := cmd.Output()
		if err == nil {
			ancestors = strings.TrimSpace(string(output))
		}
	}
	return
}

func setupCrashHandler() (crashFile *os.File) {
	crashPath := filepath.Join("bruh_output", "crash.log")
	crashFile, err := os.Create(crashPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating crash log: %v\n", err)
		return nil
	}

	// Detailed panic recovery
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(crashFile, "=== CRASH REPORT ===\n")
			fmt.Fprintf(crashFile, "Time: %s\n", time.Now().Format(time.RFC3339))
			fmt.Fprintf(crashFile, "Reason: Unexpected panic occurred\n")
			fmt.Fprintf(crashFile, "Panic: %v\n\n", r)
			
			fmt.Fprintf(crashFile, "=== PROGRAM STATE ===\n")
			fmt.Fprintf(crashFile, "Processing started at: %s\n", startTime.Format(time.RFC3339))
			fmt.Fprintf(crashFile, "Elapsed time: %s\n", time.Since(startTime).Round(time.Second))
			
			mu.Lock()
			fmt.Fprintf(crashFile, "Domains processed: %d/%d (%.2f%%)\n", processed, totalDomains, 
				float64(processed)*100/float64(totalDomains))
			mu.Unlock()
			
			workerMutex.Lock()
			fmt.Fprintf(crashFile, "Worker count: %d\n", workerCount)
			workerMutex.Unlock()
			
			fmt.Fprintf(crashFile, "CPU cap: %.1f%%\n", cpuCap)
			fmt.Fprintf(crashFile, "Min rate: %.1f domains/sec\n", minRate)
			
			fmt.Fprintf(crashFile, "\n=== STACK TRACE ===\n")
			debug.PrintStack()
			
			fmt.Fprintf(crashFile, "\n=== SYSTEM INFO ===\n")
			fmt.Fprintf(crashFile, "GOOS: %s\n", runtime.GOOS)
			fmt.Fprintf(crashFile, "GOARCH: %s\n", runtime.GOARCH)
			fmt.Fprintf(crashFile, "Go version: %s\n", runtime.Version())
			fmt.Fprintf(crashFile, "Num CPU: %d\n", runtime.NumCPU())
			fmt.Fprintf(crashFile, "Num goroutines: %d\n", runtime.NumGoroutine())
			
			crashFile.Close()
			os.Exit(1)
		}
	}()

	// Signal handling
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-signalChan
		
		// Get process tree info before we start writing to crash file
		pid, name, ancestors := getProcessTreeInfo()
		
		fmt.Fprintf(crashFile, "=== CRASH REPORT ===\n")
		fmt.Fprintf(crashFile, "Time: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(crashFile, "Reason: Received signal: %v\n", sig)
		
		// Detailed signal explanation
		switch sig {
		case syscall.SIGINT:
			fmt.Fprintf(crashFile, "Explanation: SIGINT (Interrupt signal) - Typically sent when user presses Ctrl+C\n")
			fmt.Fprintf(crashFile, "Possible sources:\n")
			fmt.Fprintf(crashFile, "  - User manually terminated the program\n")
			fmt.Fprintf(crashFile, "  - Terminal session was closed\n")
			fmt.Fprintf(crashFile, "  - Process was interrupted by system tools\n")
		case syscall.SIGTERM:
			fmt.Fprintf(crashFile, "Explanation: SIGTERM (Termination signal) - Sent to request process termination\n")
			fmt.Fprintf(crashFile, "Possible sources:\n")
			fmt.Fprintf(crashFile, "  - System shutdown/reboot initiated\n")
			fmt.Fprintf(crashFile, "  - Process manager (systemd, task manager) requested termination\n")
			fmt.Fprintf(crashFile, "  - Container orchestration system (Docker, Kubernetes) stopped container\n")
			fmt.Fprintf(crashFile, "  - Resource constraints (OOM killer, CPU limits)\n")
		default:
			fmt.Fprintf(crashFile, "Explanation: Unexpected signal received\n")
			fmt.Fprintf(crashFile, "Possible sources:\n")
			fmt.Fprintf(crashFile, "  - System-level event (hardware failure, kernel panic)\n")
			fmt.Fprintf(crashFile, "  - External process sent signal\n")
			fmt.Fprintf(crashFile, "  - Programming error in signal handling\n")
		}
		
		// Attempt to identify signal source
		fmt.Fprintf(crashFile, "\n=== SIGNAL SOURCE ANALYSIS ===\n")
		if pid > 0 {
			fmt.Fprintf(crashFile, "Parent process ID: %d\n", pid)
			fmt.Fprintf(crashFile, "Parent process name: %s\n", name)
			
			if ancestors != "" {
				fmt.Fprintf(crashFile, "Process tree:\n%s\n", ancestors)
			}
			
			if name != "unknown" {
				// Analyze based on process name
				nameLower := strings.ToLower(name)
				switch {
				case strings.Contains(nameLower, "explorer.exe"):
					fmt.Fprintf(crashFile, "Analysis: Likely user-initiated termination via Task Manager\n")
				case strings.Contains(nameLower, "cmd.exe") || strings.Contains(nameLower, "powershell.exe"):
					fmt.Fprintf(crashFile, "Analysis: Likely user-initiated termination from command line\n")
				case strings.Contains(nameLower, "systemd") || strings.Contains(nameLower, "init"):
					fmt.Fprintf(crashFile, "Analysis: Likely system-initiated termination (service manager)\n")
				case strings.Contains(nameLower, "docker") || strings.Contains(nameLower, "kube"):
					fmt.Fprintf(crashFile, "Analysis: Likely container orchestration system termination\n")
				case strings.Contains(nameLower, "sshd") || strings.Contains(nameLower, "terminal"):
					fmt.Fprintf(crashFile, "Analysis: Likely user-initiated termination from remote session\n")
				case strings.Contains(nameLower, "taskmgr.exe"):
					fmt.Fprintf(crashFile, "Analysis: Confirmed user-initiated termination via Task Manager\n")
				case strings.Contains(nameLower, "services.exe"):
					fmt.Fprintf(crashFile, "Analysis: Windows Service Control Manager termination\n")
				case strings.Contains(nameLower, "wininit.exe"):
					fmt.Fprintf(crashFile, "Analysis: Windows system shutdown process\n")
				case strings.Contains(nameLower, "oom_reaper"):
					fmt.Fprintf(crashFile, "Analysis: Linux Out-Of-Memory killer terminated the process\n")
				default:
					fmt.Fprintf(crashFile, "Analysis: Unknown source - PID %d (%s)\n", pid, name)
				}
			}
		} else {
			fmt.Fprintf(crashFile, "Could not determine parent process information\n")
		}
		
		fmt.Fprintf(crashFile, "\n=== PROGRAM STATE ===\n")
		fmt.Fprintf(crashFile, "Processing started at: %s\n", startTime.Format(time.RFC3339))
		fmt.Fprintf(crashFile, "Elapsed time: %s\n", time.Since(startTime).Round(time.Second))
		
		mu.Lock()
		fmt.Fprintf(crashFile, "Domains processed: %d/%d (%.2f%%)\n", processed, totalDomains, 
			float64(processed)*100/float64(totalDomains))
		mu.Unlock()
		
		workerMutex.Lock()
		fmt.Fprintf(crashFile, "Worker count: %d\n", workerCount)
		workerMutex.Unlock()
		
		fmt.Fprintf(crashFile, "CPU cap: %.1f%%\n", cpuCap)
		fmt.Fprintf(crashFile, "Min rate: %.1f domains/sec\n", minRate)
		
		fmt.Fprintf(crashFile, "\n=== STACK TRACE ===\n")
		debug.PrintStack()
		
		fmt.Fprintf(crashFile, "\n=== SYSTEM INFO ===\n")
		fmt.Fprintf(crashFile, "GOOS: %s\n", runtime.GOOS)
		fmt.Fprintf(crashFile, "GOARCH: %s\n", runtime.GOARCH)
		fmt.Fprintf(crashFile, "Go version: %s\n", runtime.Version())
		fmt.Fprintf(crashFile, "Num CPU: %d\n", runtime.NumCPU())
		fmt.Fprintf(crashFile, "Num goroutines: %d\n", runtime.NumGoroutine())
		
		fmt.Fprintf(crashFile, "\n=== TROUBLESHOOTING ===\n")
		fmt.Fprintf(crashFile, "1. Check system logs for resource issues (memory, CPU)\n")
		fmt.Fprintf(crashFile, "2. Verify available disk space in output directory\n")
		fmt.Fprintf(crashFile, "3. Review domain processing logs for errors\n")
		fmt.Fprintf(crashFile, "4. Consider reducing worker count if system is overloaded\n")
		fmt.Fprintf(crashFile, "5. Check for external factors (system shutdown, process killers)\n")
		
		crashFile.Close()
		os.Exit(1)
	}()

	return crashFile
}

func main() {
	outputDir := "bruh_output"
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %s\n", err)
		return
	}

	// Setup crash handler
	crashFile := setupCrashHandler()
	if crashFile != nil {
		defer crashFile.Close()
	}

	// Main log file
	logFilePath := filepath.Join(outputDir, "dnslookup_verdict.log")
	var err error
	logFile, err = os.Create(logFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating log file: %v\n", err)
		return
	}
	defer logFile.Close()

	// Rate log file
	rateLogPath := filepath.Join(outputDir, "rate.log")
	rateLogFile, err = os.Create(rateLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating rate log file: %v\n", err)
		return
	}
	defer rateLogFile.Close()

	// 1. Enhanced domain cross-referencing
	fmt.Println("Loading existing domains for cross-referencing...")
	if err := loadExistingDomains(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading existing domains: %v\n", err)
	}
	fmt.Printf("Loaded %d existing domains for deduplication\n", len(existingDomains))

	domainsFilePath := filepath.Join(outputDir, "domains.txt")
	mainFile, err = os.OpenFile(domainsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening domains.txt: %s\n", err)
		return
	}
	defer mainFile.Close()

	// Read input domains
	domains, err := readDomains("domains.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading domains.txt: %v\n", err)
		return
	}

	totalDomains = len(domains)
	if totalDomains == 0 {
		fmt.Println("No new domains found in domains.txt after deduplication")
		return
	}
	fmt.Printf("Found %d domains in input file after deduplication\n", totalDomains)

	// Start with a high number of workers
	initialWorkers := 200
	if initialWorkers > totalDomains {
		initialWorkers = totalDomains
	}

	domainsChan := make(chan string, initialWorkers*2)
	var wg sync.WaitGroup

	startTime = time.Now()
	fmt.Printf("Starting processing of %d new domains...\n", totalDomains)
	fmt.Printf("Log file: %s\n", logFilePath)
	fmt.Printf("Rate log: %s\n", rateLogPath)
	fmt.Printf("Crash log: %s\n", filepath.Join(outputDir, "crash.log"))
	fmt.Printf("CPU Cap: %.1f%%\n", cpuCap)
	fmt.Printf("Min Rate: %.1f domains/sec\n", minRate)

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	workerMutex.Lock()
	workerCount = initialWorkers
	for i := 0; i < initialWorkers; i++ {
		workerCtx, cancel := context.WithCancel(baseCtx)
		workerCancels = append(workerCancels, cancel)
		wg.Add(1)
		go worker(workerCtx, &wg, domainsChan)
	}
	workerMutex.Unlock()

	adjusterCtx, adjusterCancel := context.WithCancel(baseCtx)
	defer adjusterCancel()
	go adjustWorkers(adjusterCtx, baseCtx, &wg, domainsChan)

	// Start rate logging
	go logRateStats()

	// Send domains
	go func() {
		for _, domain := range domains {
			domainsChan <- domain
		}
		close(domainsChan)
	}()

	// Progress tracking with cmdLoop
	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- nil
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Variables for ETA calculation
	var (
		lastProcessedCount = 0
		lastProgressTime   = time.Now()
		smoothedRate       = 0.0
		lastETAUpdate      = time.Now()
		currentETA         = time.Duration(0)
		cumulativeDomains  = 0
		cumulativeTime     = 0.0
	)

cmdLoop:
	for {
		select {
		case <-ticker.C:
			mu.Lock()
			current := processed
			mu.Unlock()

			if totalDomains == 0 {
				fmt.Printf("\rWaiting for domains...")
				continue
			}

			percent := float64(current) * 100 / float64(totalDomains)
			if percent > 100 {
				percent = 100
			}

			filled := int(percent * float64(barWidth) / 100)
			if filled > barWidth {
				filled = barWidth
			}
			bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)

			now := time.Now()
			elapsed := now.Sub(lastProgressTime).Seconds()
			currentRate := 0.0
			if elapsed > 0 {
				currentRate = float64(current-lastProcessedCount) / elapsed
			}

			// Calculate smoothed rate using exponential smoothing
			if smoothedRate == 0 {
				smoothedRate = currentRate
			} else if elapsed > 0 {
				smoothedRate = smoothingFactor*currentRate + (1-smoothingFactor)*smoothedRate
			}

			// Update cumulative stats for global average
			cumulativeDomains += current - lastProcessedCount
			cumulativeTime += elapsed

			// Update ETA every 5 seconds using global average
			if now.Sub(lastETAUpdate) >= etaUpdatePeriod {
				if cumulativeTime > 0 {
					// Calculate global average rate using all samples
					globalRate := float64(cumulativeDomains) / cumulativeTime
					if globalRate > 0 {
						remainingDomains := totalDomains - current
						remainingTime := float64(remainingDomains) / globalRate
						currentETA = time.Duration(remainingTime) * time.Second
					}
				}
				lastETAUpdate = now
			}

			// Format ETA for display
			etaStr := "N/A"
			if currentETA > 0 {
				etaStr = currentETA.Round(time.Second).String()
			}

			workerMutex.Lock()
			workerCountCurrent := workerCount
			workerMutex.Unlock()

			fmt.Printf("\r[%s] %.2f%% %d/%d domains (workers: %d, %.2f/s) ETA: %s",
				bar, percent, current, totalDomains, workerCountCurrent, smoothedRate, etaStr)

			// Update for next calculation
			lastProcessedCount = current
			lastProgressTime = now

		case err := <-done:
			if err != nil {
				fmt.Printf("\nError: %v\n", err)
				return
			}
			break cmdLoop
		}
	}

	current := processed
	percent := float64(current) * 100 / float64(totalDomains)
	if percent > 100 {
		percent = 100
	}
	bar := strings.Repeat("=", barWidth)
	elapsedTotal := time.Since(startTime)
	rate := float64(current) / elapsedTotal.Seconds()
	
	workerMutex.Lock()
	workerCountCurrent := workerCount
	workerMutex.Unlock()
	
	fmt.Printf("\r[%s] %.2f%% %d/%d domains (workers: %d, %.2f/s, total time: %s)\n",
		bar, percent, current, totalDomains, workerCountCurrent, rate, elapsedTotal.Round(time.Second))

	for status, f := range statusFiles {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file for status '%s': %v\n", status, err)
		}
	}

	fmt.Printf("Processing complete. Processed %d new domains.\n", processed)
}