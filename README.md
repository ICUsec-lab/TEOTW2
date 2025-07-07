# TEOTW2 - XSS Crawler & Scanner

TEOTW2 is a Python-based web crawler and XSS vulnerability scanner that supports crawling scoped domains, injecting XSS payloads, and saving results to a file.

---

## 🚀 Features

- ✅ URL crawling with scope restriction
- ✅ GET-based XSS parameter testing
- ✅ Multi-payload XSS scanning
- ✅ Clear output modes for cleaner results
- ✅ File output support with screen printing
- ✅ Optional separation of crawled URLs and XSS results
- ✅ Logo display (not saved to output file)

---

## 📦 Installation

```bash
git clone https://github.com/ICUsec-lab/TEOTW2.git
cd TEOTW2
pip install -r requirements.txt
```

#### Requirements:
    Python 3
    requests
    beautifulsoup4

## 🛠️ Usage
```bash
python teotw3.py -u <url> --scope <domain> [options]
```
### 📌 Options:
```bash
Option	        Description
-u, --url	Base URL to scan (required)
--scope	        Scope domain to limit crawling (required)
--xss	        Enable XSS scanning
--crawl	        Enable crawling
-m, --method	HTTP method to use (default: GET)
-p, --pages	Max number of pages to crawl (default: 50)
--clear	        Show clean output (minimal messages)
--clear-separate	Separate crawled URLs and XSS results
-o, --output	Save output to file (logo not saved)
```


## 📂 Examples
#### Crawl + XSS Scan + Save Output to File
```bash
python teotw3.py -u http://example.com/ --scope example.com --crawl --xss -o results.txt
```

#### Crawl Only 
```bash
python teotw3.py -u http://example.com/ --scope example.com --crawl
```

#### XSS Scan Only
```bash
python teotw3.py -u "http://example.com/product.php?pic=1" --scope example.com --xss
```

## ✅ Notes:
The logo is always displayed on the screen.
When using -o, the logo is **not** saved to the file (file only contains results).
Both screen output and file output happen when -o is used.

## ⚠️ Legal Disclaimer
This tool is intended for **__educational purposes only__** and authorized security testing only. Usage on unauthorized targets is strictly prohibited.
