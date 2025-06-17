# kxss
`kxss` is a Go-based tool designed to identify reflected URL query parameters and detect unfiltered characters that could indicate potential Cross-Site Scripting (XSS) vulnerabilities. It processes URLs provided via standard input or a file, checks if query parameters are reflected in the HTTP response body, and tests for unfiltered characters that may allow XSS payloads. The tool is particularly useful in security testing workflows, such as those involving URL crawling with tools like katana.
#### Install
```
go mod init kxss.go && go mod tidy && go build -o kxss
```
#### Usage
```
./kxss -h

-f string     file containing URLs to process
-o string     file to write output to
```
#### Workflow with Katana
`kxss` integrates well with `katana`, a web crawler for discovering URLs. 

Passive or active crawl a target domain with `katana` to extract URLs with query parameters:
```
katana -u vulnweb.com -ps -f qurl -o katana_passive_crawl.txt && uro -i katana_passive_crawl.txt -o katana_passive.txt

katana -u http://testphp.vulnweb.com -f qurl -o katana_active_crawl.txt && uro -i katana_active_crawl.txt -o katana_active.txt
```
Run `kxss` on the output file:
```
./kxss -f katana_passive.txt

./kxss -f katana_active.txt -o reflected_parameters.txt
```
Alternatively, pipe `katana` output directly:
```
katana -u vulnweb.com -ps -f qurl | ./kxss
```
