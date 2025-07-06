#!/usr/bin/env python3
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import argparse
import multiprocessing
import sys

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

def get_links(url):
    try:
        resp = requests.get(url, verify=False, timeout=8)
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        base_url = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(url))
        links = set()
        for tag in soup.find_all("a", href=True):
            href = tag.get("href")
            if href.startswith(("javascript:", "#", "mailto:")):
                continue
            joined = urljoin(url, href).split('#')[0]
            if urlparse(joined).netloc == urlparse(base_url).netloc:
                links.add(joined)
        return list(links)
    except Exception as e:
        print(f"[!] Failed to get links from {url}: {e}", file=sys.stderr)
        return []

def crawl(url, max_depth, current_depth=0, visited=None, scope=None, clear=False):
    if visited is None:
        visited = set()
    if current_depth > max_depth:
        return visited
    if url in visited:
        return visited
    if scope and scope.lower() not in urlparse(url).netloc.lower():
        return visited
    visited.add(url)
    if clear:
        print(url)
    else:
        print(f"[CRAWL] Depth {current_depth}: {url}")
    links = get_links(url)
    for link in links:
        crawl(link, max_depth, current_depth + 1, visited, scope, clear)
    return visited

def scan_xss_url(args):
    url, method, payloads, scope = args
    results = []
    if scope and scope.lower() not in urlparse(url).netloc.lower():
        return results
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if method.lower() == "get" and query:
        for param in query:
            for payload in payloads:
                new_query = query.copy()
                new_query[param] = [payload]
                new_query_enc = urlencode(new_query, doseq=True)
                test_url = parsed._replace(query=new_query_enc).geturl()
                try:
                    r = requests.get(test_url, verify=False, timeout=8)
                    if payload in r.text:
                        results.append(f"{test_url} [param: {param}] [payload: {payload}]")
                        break
                except Exception:
                    continue
    elif method.lower() == "post":
        data = {param: "test" for param in query}
        for param in query:
            for payload in payloads:
                data[param] = payload
                try:
                    r = requests.post(url, data=data, verify=False, timeout=8)
                    if payload in r.text:
                        results.append(f"{url} [param: {param}] [payload: {payload}]")
                        break
                except Exception:
                    continue
                data[param] = "test"
    return results

def main():
    parser = argparse.ArgumentParser(description="XSS crawler and scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("-m", "--method", choices=["get", "post"], default="get", help="HTTP method for XSS scanning")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for XSS payloads")
    parser.add_argument("-p", "--processes", type=int, default=5, help="Parallel scan processes")
    parser.add_argument("--crawl", action="store_true", help="Perform crawl only")
    parser.add_argument("--xss", action="store_true", help="Perform XSS scan only")
    parser.add_argument("--clear", action="store_true", help="Simplify output (no crawl depth info)")
    parser.add_argument("--clear-separate", action="store_true", help="Print crawl and XSS URLs plainly, implies --clear")
    parser.add_argument("--scope", help="Limit crawling/scanning URLs to domain substring")
    args = parser.parse_args()

    # If --clear-separate is set, automatically enable --clear and print note once
    if args.clear_separate:
        if not args.clear:
            print("[*] Note: --clear-separate implies --clear, so --clear enabled automatically.")
        args.clear = True

    if args.crawl and not args.xss and args.wordlist:
        print("[*] Note: Wordlist (-w) is not needed when running crawl only (--crawl). It will be ignored.")

    if args.xss:
        if args.wordlist:
            try:
                with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    payloads = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[!] Error reading wordlist: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            payloads = DEFAULT_PAYLOADS
    else:
        payloads = []

    if not args.crawl and not args.xss:
        do_crawl = True
        do_xss = True
    else:
        do_crawl = args.crawl
        do_xss = args.xss

    crawled_urls = set()
    if do_crawl:
        crawled_urls = crawl(args.url, args.depth, scope=args.scope, clear=args.clear)
        crawled_urls = sorted(crawled_urls)
        if not args.clear_separate:
            print("\n[Crawl URLs Found:]")
            for u in crawled_urls:
                print(u)

    if do_xss and not do_crawl:
        urls_to_scan = [args.url]
        if args.scope:
            urls_to_scan = [u for u in urls_to_scan if args.scope.lower() in urlparse(u).netloc.lower()]
    elif do_xss:
        urls_to_scan = crawled_urls
    else:
        urls_to_scan = []

    if do_xss:
        if not urls_to_scan:
            if args.clear_separate:
                print("# No URLs found to scan for XSS.")
            else:
                print("\nNo URLs found to scan for XSS.")
            return

        tasks = [(url, args.method, payloads, args.scope) for url in urls_to_scan]
        with multiprocessing.Pool(args.processes) as pool:
            results = pool.map(scan_xss_url, tasks)

        found_any = False
        if args.clear_separate:
            for res_list in results:
                for res in res_list:
                    print(res)
                    found_any = True
            if not found_any:
                print("# No XSS vulnerabilities found.")
        else:
            print("\n# XSS URLs Found:")
            for res_list in results:
                for res in res_list:
                    print(res)
                    found_any = True
            if not found_any:
                print("No XSS vulnerabilities found.")

if __name__ == "__main__":
    main()
