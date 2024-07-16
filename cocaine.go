package main

import (
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "sync"
    "github.com/PuerkitoBio/goquery"
)

var wg sync.WaitGroup

func main() {
    mailDomain := flag.String("t", "", "Mail domain to scan")
    subDomain := flag.String("s", "", "Subdomain to scan")
    combine := flag.Bool("c", false, "Combine results")
    outputFile := flag.String("o", "output.txt", "Output file")

    flag.Parse()

    if *mailDomain == "" && *subDomain == "" {
        fmt.Println("Please provide a mail domain or subdomain to scan.")
        return
    }

    urls := []string{}
    if *mailDomain != "" {
        urls = append(urls, *mailDomain)
    }
    if *subDomain != "" {
        urls = append(urls, *subDomain)
    }

    results := make(chan string)
    go func() {
        for _, url := range urls {
            wg.Add(1)
            go scanURL(url, results)
        }
        wg.Wait()
        close(results)
    }()

    uniqueResults := make(map[string]struct{})
    for result := range results {
        if *combine {
            if _, exists := uniqueResults[result]; !exists {
                uniqueResults[result] = struct{}{}
            }
        } else {
            uniqueResults[result] = struct{}{}
        }
    }

    err := writeToFile(*outputFile, uniqueResults)
    if err != nil {
        log.Printf("Failed to write to file: %v", err)
    } else {
        fmt.Printf("Results written to %s\n", *outputFile)
    }
}

func scanURL(url string, results chan<- string) {
    defer wg.Done()
    res, err := http.Get(url)
    if err != nil {
        log.Printf("Failed to scan %s: %v", url, err)
        return
    }
    defer res.Body.Close()

    if res.StatusCode != 200 {
        log.Printf("Failed to get a valid response from %s: %d %s", url, res.StatusCode, res.Status)
        return
    }

    doc, err := goquery.NewDocumentFromReader(res.Body)
    if err != nil {
        log.Printf("Failed to parse response from %s: %v", url, err)
        return
    }

    doc.Find("a").Each(func(i int, s *goquery.Selection) {
        href, exists := s.Attr("href")
        if exists {
            results <- href
        }
    })

    scanForHiddenFiles(url, results)
}

func scanForHiddenFiles(url string, results chan<- string) {
    hiddenFiles := []string{"/robots.txt", "/.htaccess", "/.git", "/.env"}
    for _, file := range hiddenFiles {
        fullURL := strings.TrimRight(url, "/") + file
        res, err := http.Get(fullURL)
        if err != nil {
            log.Printf("Failed to scan %s: %v", fullURL, err)
            continue
        }
        if res.StatusCode == 200 {
            results <- fullURL
        }
        res.Body.Close()
    }
}

func writeToFile(filename string, data map[string]struct{}) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    for line := range data {
        _, err := file.WriteString(line + "\n")
        if err != nil {
            return err
        }
    }
    return nil
}
