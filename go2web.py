#!/usr/bin/env python3
import sys
import socket
import urllib.parse
import re
from html.parser import HTMLParser
import json
import os
import time
import ssl
import gzip
import io
import zlib
import html
from argparse import ArgumentParser, RawDescriptionHelpFormatter

class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.text = []
        self.skip_tags = ['script', 'style', 'head', 'meta', 'link']
        self.current_tag = None
        self.current_attrs = None
        self.bold = False
        self.italic = False
        self.link_url = None

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        self.current_attrs = dict(attrs)
        
        if tag == 'strong' or tag == 'b':
            self.bold = True
        elif tag == 'em' or tag == 'i':
            self.italic = True
        elif tag == 'a' and 'href' in self.current_attrs:
            self.link_url = self.current_attrs['href']
            

    def handle_endtag(self, tag):
        if tag == 'strong' or tag == 'b':
            self.bold = False
        elif tag == 'em' or tag == 'i':
            self.italic = False
        elif tag == 'a':
            self.link_url = None
            
        self.current_tag = None
        if tag in ['p', 'br', 'div', 'section', 'article', 'li']:
            self.text.append('\n')

    def handle_data(self, d):
        if self.current_tag not in self.skip_tags and d.strip():
            text = d.strip()
            
            # Apply formatting
            if self.bold:
                text = f'*{text}*'
            if self.italic:
                text = f'_{text}_'
                
            # Handle links
            if self.link_url and self.current_tag == 'a':
                text = f'{text} ({self.link_url})'
                
            self.text.append(text.strip())

    def get_text(self):
        return ' '.join(self.text)

class HTTPClient:
    @staticmethod
    def parse_url(url):
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path += '?' + parsed.query
        return host, path, parsed.scheme == 'https'

    @staticmethod
    def make_request(host, path, headers=None, method='GET', https=False):
        port = 443 if https else 80
        
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        if https:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        
        sock.connect((host, port))
        
        # Build request
        request_lines = [
            f'{method} {path} HTTP/1.1',
            f'Host: {host}',
            'Connection: close',
            'User-Agent: go2web/1.0'
        ]
        
        if headers:
            for key, value in headers.items():
                request_lines.append(f'{key}: {value}')
        
        request = '\r\n'.join(request_lines) + '\r\n\r\n'
        
        # Send request
        sock.sendall(request.encode())
        
        # Receive response
        response = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        sock.close()
        return response.decode('utf-8', errors='ignore')

    @staticmethod
    def parse_response(response):
        headers_raw, _, body = response.partition('\r\n\r\n')
        headers_lines = headers_raw.split('\r\n')
        
        status_line = headers_lines[0] if headers_lines else ''
        try:
            status_code = int(status_line.split()[1]) if status_line else 500
        except (IndexError, ValueError):
            status_code = 500
        
        headers = {}
        for line in headers_lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value
        
        # Handle content encoding
        content_encoding = headers.get('content-encoding', '').lower()
        if content_encoding == 'gzip':
            try:
                body = gzip.GzipFile(fileobj=io.BytesIO(body.encode('latin1'))).read().decode('utf-8')
            except:
                pass
        elif content_encoding == 'deflate':
            try:
                body = zlib.decompress(body.encode('latin1')).decode('utf-8')
            except:
                pass
        
        return {
            'status_code': status_code,
            'headers': headers,
            'body': body
        }

    @staticmethod
    def follow_redirects(url, max_redirects=5, headers=None):
        current_url = url
        for _ in range(max_redirects):
            host, path, https = HTTPClient.parse_url(current_url)
            response = HTTPClient.make_request(host, path, headers, https=https)
            parsed = HTTPClient.parse_response(response)
            
            if parsed['status_code'] in (301, 302, 303, 307, 308):
                location = parsed['headers'].get('location')
                if not location:
                    break
                
                if location.startswith('/'):
                    current_url = f'http{"s" if https else ""}://{host}{location}'
                else:
                    current_url = location
            else:
                return parsed['body'], current_url
        
        return parsed['body'], current_url

class CacheManager:
    CACHE_DIR = '.go2web_cache'
    
    @staticmethod
    def _get_cache_path(key):
        if not os.path.exists(CacheManager.CACHE_DIR):
            os.makedirs(CacheManager.CACHE_DIR)
        safe_key = re.sub(r'[^a-zA-Z0-9]', '_', key)
        return os.path.join(CacheManager.CACHE_DIR, safe_key)
    
    @staticmethod
    def get(key):
        path = CacheManager._get_cache_path(key)
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
                if data['expiry'] > time.time():
                    return data['content']
        return None
    
    @staticmethod
    def set(key, content, ttl=3600):
        path = CacheManager._get_cache_path(key)
        data = {
            'content': content,
            'expiry': time.time() + ttl
        }
        with open(path, 'w') as f:
            json.dump(data, f)

def clean_text(text):
    """Clean text by removing excessive whitespace and unescaping HTML entities"""
    text = html.unescape(text)
    text = text.replace("\\u003Cstrong>", "").replace("\\u003C/strong>", "")
    return text

def fetch_url(url):
    cache_key = f'url:{url}'
    cached = CacheManager.get(cache_key)
    if cached:
        return cached
    
    try:
        headers = {'Accept': 'text/html,application/json'}
        body, final_url = HTTPClient.follow_redirects(url, headers=headers)
        
        # Handle content type
        host, path, https = HTTPClient.parse_url(final_url)
        response = HTTPClient.make_request(host, path, headers, https=https)
        parsed = HTTPClient.parse_response(response)
        
        content_type = parsed['headers'].get('content-type', '').split(';')[0]
        
        if content_type == 'application/json':
            try:
                data = json.loads(parsed['body'])
                result = json.dumps(data, indent=2)
            except json.JSONDecodeError:
                result = clean_text(parsed['body'])
        else:
            # Extract text from HTML
            extractor = HTMLTextExtractor()
            extractor.feed(parsed['body'])
            result = extractor.get_text()
            result = clean_text(result)
        
        CacheManager.set(cache_key, result)
        return result
    except Exception as e:
        return f"Error fetching URL: {str(e)}"

def search_term(term):
    cache_key = f'search:{term}'
    cached = CacheManager.get(cache_key)
    if cached:
        return cached
   
    try:
        # Use Brave Search as an alternative
        base_url = "https://search.brave.com/search"
        params = {
            'q': term,
            'source': 'web'
        }
       
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
        }
       
        host, path, https = HTTPClient.parse_url(base_url)
        query_string = urllib.parse.urlencode(params)
        full_path = f"{path}?{query_string}"
       
        response = HTTPClient.make_request(host, full_path, headers, https=True)
        parsed_response = HTTPClient.parse_response(response)
        body = parsed_response['body']
       
        # Try to find JSON-like data in the response
        results = []
        
        # First attempt: Look for structured data patterns
        data_pattern = re.compile(r'\{.*?title:\s*"(?P<title>.*?)".*?url:\s*"(?P<url>.*?)".*?description:\s*"(?P<desc>.*?)".*?\}', re.DOTALL)
        matches = list(data_pattern.finditer(body))
        
        for i, match in enumerate(matches[:10]):
            title = clean_text(match.group('title'))
            url = clean_text(match.group('url'))
            desc = clean_text(match.group('desc'))
            
            results.append(f"{i+1}. *{title}*\n   {url}\n   {desc}\n")
        
        # Second attempt: If no structured data found, try to find raw JSON
        if not results:
            json_pattern = re.compile(r'\{.*?"results":\s*\[(.*?)\].*?\}', re.DOTALL)
            json_match = json_pattern.search(body)
            if json_match:
                try:
                    # Try to parse the JSON data
                    json_data = json.loads(f'{{{json_match.group(0)}}}')
                    if 'results' in json_data:
                        for i, item in enumerate(json_data['results'][:10]):
                            title = clean_text(item.get('title', ''))
                            url = clean_text(item.get('url', ''))
                            desc = clean_text(item.get('description', ''))
                            results.append(f"{i+1}. *{title}*\n   {url}\n   {desc}\n")
                except json.JSONDecodeError:
                    pass
        
        # Fallback to HTML parsing if no structured data found
        if not results:
            # HTML fallback parsing (similar to original but improved)
            result_pattern = re.compile(
                r'<div[^>]*class=".*?result.*?".*?>.*?'
                r'<a[^>]*href="([^"]*)"[^>]*>.*?'
                r'<h3[^>]*>(.*?)</h3>.*?'
                r'<p[^>]*>(.*?)</p>',
                re.DOTALL
            )
            matches = list(result_pattern.finditer(body))
            
            for i, match in enumerate(matches[:10]):
                url = clean_text(match.group(1).strip())
                title = clean_text(match.group(2).strip())
                snippet = clean_text(match.group(3).strip())
                results.append(f"{i+1}. *{title}*\n   {url}\n   {snippet}\n")
       
        if not results:
            return "No results found. Try a different search term."
       
        result = "Top Results:\n" + '\n'.join(results)
        CacheManager.set(cache_key, result)
        return result
       
    except Exception as e:
        return f"Search error: {str(e)}"

def main():
    parser = ArgumentParser(
        description='go2web - a simple CLI web utility',
        formatter_class=RawDescriptionHelpFormatter,
        epilog='''Examples:
  go2web -u example.com
  go2web -s "search term"
  go2web -u https://api.example.com/data.json''')
    
    parser.add_argument('-u', '--url', help='make an HTTP request to the specified URL and print the response')
    parser.add_argument('-s', '--search', help='search the term using DuckDuckGo and print top results', nargs='+')
    parser.add_argument('-l', '--link', type=int, help='open a link from the last search results (1-10)')
    
    args = parser.parse_args()
    
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)
    
    if args.url:
        result = fetch_url(args.url)
        print(result)
    
    if args.search:
        term = ' '.join(args.search)
        result = search_term(term)
        print(result)
        
        if args.link:
            # Extract URLs from search results
            urls = re.findall(r'https?://[^\s]+', result)
            if 1 <= args.link <= len(urls):
                selected_url = urls[args.link-1]
                print(f"\nFetching link #{args.link}: {selected_url}\n")
                print(fetch_url(selected_url))
            else:
                print(f"Invalid link number. Choose between 1-{len(urls)}")

if __name__ == '__main__':
    main()