# ParamFuzzing 🚀
**Web Parameter Discovery & Fuzzing Toolkit**

---

## 📚 Description
ParamFuzzing is a comprehensive toolkit for **web parameter discovery, crawling, and XSS fuzzing**. It combines advanced crawling, scope control, and parameter-based vulnerability scanning into a simple, flexible interface.

This toolkit was created to streamline the process of:
- 🌐 Crawling web applications.
- 🔍 Extracting GET/POST parameters.
- 💉 Fuzzing parameters for XSS.
- ⚙️ Supporting multi-threaded and wordlist-based fuzzing.

---

## 🛠️ Features
- Intelligent crawling with depth control.
- Multi-threaded XSS scanning.
- URL scope filtering.
- Supports GET/POST methods.
- Seamless chaining between crawling and fuzzing.
- Easy integration with other tools.

---

## 🚀 Usage Examples
### 🕷️ Crawl Only
```bash
python teotw2.py -u https://example.com -m get -d 2 --scope example.com --crawl
```
### 💉 XSS Scan Only
```bash
python teotw2.py -u https://example.com -m get -d 2 --scope example.com --xss -w payloads.txt -p 10
```
### ⚡ Quick XSS Scanner
``` bash
python xss_scanner.py -u https://example.com -p param1,param2
```

### 📦 Requirements
```bash
pip install -r requirements.txt
```


## 📣 Credits
Developed by @ICUsec-lab
This tool is for educational and authorized testing purposes only.

## ⚠️ Disclaimer
The creator is not responsible for any misuse of this tool. Use responsibly and only on systems you are authorized to test.
