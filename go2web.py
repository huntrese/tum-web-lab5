#!/usr/bin/env python3
import argparse
import socket
import ssl
import re
import os
import json
import time
import html
import random
import gzip
import io
from urllib.parse import urlparse, urlencode, quote_plus

# Constants
USER_AGENT_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
]
USER_AGENT = random.choice(USER_AGENT_LIST)
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".go2web_cache")
CACHE_EXPIRY = 3600  # Cache expiry in seconds (1 hour)

# Cache mechanism
class HttpCache:
    def __init__(self):
        if not os.path.exists(CACHE_DIR):
            os.makedirs(CACHE_DIR)
    
    def _get_cache_filename(self, url):
        return os.path.join(CACHE_DIR, quote_plus(url))
    
    def get(self, url):
        cache_file = self._get_cache_filename(url)
        if os.path.exists(cache_file):
            # Check if cache is still valid
            file_time = os.path.getmtime(cache_file)
            if time.time() - file_time < CACHE_EXPIRY:
                with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
                    cached_data = json.load(f)
                    return cached_data['headers'], cached_data['content']
        return None, None
    
    def set(self, url, headers, content):
        cache_file = self._get_cache_filename(url)
        try:
            with open(cache_file, 'w', encoding='utf-8', errors='replace') as f:
                json.dump({
                    'headers': headers,
                    'content': content
                }, f)
        except Exception as e:
            print(f"Warning: Failed to cache response: {e}")

# Enhanced URL handling
def normalize_url(url):
    """Normalize URL by adding scheme if missing"""
    if not url:
        return None
        
    # If no protocol specified, add http://
    if not url.startswith(('http://', 'https://')):
        if url.startswith('www.'):
            url = 'https://' + url
        else:
            url = 'https://www.' + url
    
    # Make sure URL has a path
    parsed = urlparse(url)
    if not parsed.path:
        url += '/'

    return url

class HttpClient:
    def __init__(self):
        self.cookies = {}
        self.cf_retries = 0

    def make_request(self, url, headers=None, follow_redirects=True, method="GET", body=None, referer=None):
        url = self.normalize_url(url)
        if not url:
            return {}, "Invalid URL"

        parsed_url = urlparse(url)
        host = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else "/"
        if parsed_url.query:
            path += "?" + parsed_url.query

        port = 443 if parsed_url.scheme == "https" else 80

        headers = headers.copy() if headers else {}
        headers['User-Agent'] = USER_AGENT
        headers['Host'] = host
        if referer:
            headers['Referer'] = referer

        # Add more headers for better compatibility
        headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        headers.setdefault('Accept-Language', 'en-US,en;q=0.9')
        headers.setdefault('Accept-Encoding', 'gzip, deflate')

        request = f"{method} {path} HTTP/1.1\r\n"
        for header_name, header_value in headers.items():
            request += f"{header_name}: {header_value}\r\n"
        request += "Connection: close\r\n\r\n"

        if body:
            request += body

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)

        try:
            if parsed_url.scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(request.encode())

            response = b""
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break

            if not response:
                return {}, "No response received from server."

            # Split headers and body as bytes
            header_end = response.find(b'\r\n\r\n')
            if header_end == -1:
                return {}, "Invalid HTTP response"

            headers_part = response[:header_end]
            body_part = response[header_end + 4:]

            # Parse headers
            headers_str = headers_part.decode('utf-8', errors='replace')
            headers_lines = headers_str.split('\r\n')
            status_line = headers_lines[0]
            headers = {}
            for line in headers_lines[1:]:
                if ': ' in line:
                    name, value = line.split(': ', 1)
                    headers[name.lower()] = value

            # Handle gzip/deflate content
            content_encoding = headers.get('content-encoding', '').lower()
            if 'gzip' in content_encoding:
                try:
                    buf = io.BytesIO(body_part)
                    with gzip.GzipFile(fileobj=buf) as f:
                        body = f.read().decode('utf-8', errors='replace')
                except Exception as e:
                    body = body_part.decode('utf-8', errors='replace')
            elif 'deflate' in content_encoding:
                body = body_part.decode('utf-8', errors='replace')
            else:
                charset = 'utf-8'
                content_type = headers.get('content-type', '')
                if 'charset=' in content_type:
                    charset = content_type.split('charset=')[-1].split(';')[0].strip()
                try:
                    body = body_part.decode(charset, errors='replace')
                except LookupError:
                    body = body_part.decode('utf-8', errors='replace')

            status_code = int(status_line.split()[1])
            if follow_redirects and status_code in (301, 302, 303, 307, 308) and 'location' in headers:
                redirect_url = headers['location']
                print(f"Redirecting to: {redirect_url}")
                return self.make_request(redirect_url, headers, follow_redirects, method, body, referer=url)

            return headers, body

        except Exception as e:
            return {}, f"Error connecting to {url}: {str(e)}"
        finally:
            sock.close()


    def normalize_url(self, url):
        """Normalize URL by adding scheme if missing"""
        if not url:
            return None
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'https://' + url
            else:
                url = 'https://www.' + url
        return url

# Improved HTML Content Processing
class HtmlProcessor:
    def __init__(self, base_url):
        self.base_url = base_url
        self.in_script = False
        self.in_style = False
        self.in_head = False
        self.in_comment = False
        self.output_buffer = []
        self.current_text = []
        self.links = []
        self.current_link = None
        self.title = None
        
    def process_html(self, html_content):
        # Simple state machine to parse HTML
        i = 0
        while i < len(html_content):
            # Check for comments
            if i+4 <= len(html_content) and html_content[i:i+4] == '<!--':
                self.in_comment = True
                i += 4
                continue
            
            if self.in_comment and i+3 <= len(html_content) and html_content[i:i+3] == '-->':
                self.in_comment = False
                i += 3
                continue
            
            if self.in_comment:
                i += 1
                continue
            
            # Check for tag start
            if html_content[i:i+1] == '<':
                # Flush accumulated text
                if self.current_text:
                    text = ''.join(self.current_text).strip()
                    if text and not self.in_script and not self.in_style and not self.in_head:
                        if self.current_link:
                            self.links.append((text, self.current_link))
                            self.current_link = None
                        else:
                            self.output_buffer.append(text)
                    self.current_text = []
                
                # Find tag end
                tag_end = html_content.find('>', i)
                if tag_end == -1:
                    i += 1
                    continue
                
                tag = html_content[i+1:tag_end].lower().strip()
                
                # Process tag
                if tag.startswith('script'):
                    self.in_script = True
                elif tag == '/script':
                    self.in_script = False
                elif tag.startswith('style'):
                    self.in_style = True
                elif tag == '/style':
                    self.in_style = False
                elif tag.startswith('head'):
                    self.in_head = True
                elif tag == '/head':
                    self.in_head = False
                elif tag == 'title':
                    # Extract title
                    title_end = html_content.find('</title>', tag_end)
                    if title_end > tag_end:
                        self.title = html_content[tag_end+1:title_end].strip()
                elif tag.startswith('a '):
                    # Extract href
                    href_match = re.search(r'href=["\'](.*?)["\']', tag)
                    if href_match:
                        href = href_match.group(1)
                        # Handle relative URLs
                        if href.startswith('/'):
                            parsed_url = urlparse(self.base_url)
                            href = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                        elif not href.startswith(('http://', 'https://')):
                            base_url = self.base_url
                            if not base_url.endswith('/'):
                                base_url = '/'.join(base_url.split('/')[:-1]) + '/'
                            href = base_url + href
                        
                        self.current_link = href
                elif tag == '/a':
                    self.current_link = None
                elif tag in ['br', 'p', 'div', '/p', '/div', 'li', '/li']:
                    self.current_text.append("\n")
                
                i = tag_end + 1
            else:
                # Accumulate text
                if not self.in_script and not self.in_style:
                    self.current_text.append(html_content[i])
                i += 1
        
        # Process any remaining text
        if self.current_text and not self.in_script and not self.in_style and not self.in_head:
            text = ''.join(self.current_text).strip()
            if text:
                if self.current_link:
                    self.links.append((text, self.current_link))
                else:
                    self.output_buffer.append(text)
        
        return self.create_readable_output()
    
    def create_readable_output(self):
        result = []
        
        # Add page title
        if self.title:
            result.append(f"Title: {self.title}")
            result.append("=" * 40)
        
        # Add processed text
        content_added = False
        for text in self.output_buffer:
            # Decode HTML entities and clean up whitespace
            text = html.unescape(text)
            text = re.sub(r'[ \t]+', ' ', text)
            text = re.sub(r'\n{3,}', '\n\n', text)
            if text.strip():
                result.append(text)
                content_added = True
        
        # Make sure we have at least some content
        if not content_added:
            result.append("-")
        
        # Add links at the end
        if self.links:
            result.append("=" * 40)
            result.append("Links:")
            for i, (text, url) in enumerate(self.links, 1):
                # Clean up link text
                text = html.unescape(text).strip()
                text = re.sub(r'\s+', ' ', text)
                if not text:
                    text = url
                result.append(f"{i}. {text}")
        
        return '\n'.join(result)

# Main functions
def make_url_request(url):
    client = HttpClient()
    
    # Normalize URL first
    normalized_url = normalize_url(url)
    if not normalized_url:
        print(f"Invalid URL: {url}")
        return
        
    print(f"Requesting: {normalized_url}")
    
    # Enhanced headers for better site compatibility
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    headers, body = client.make_request(normalized_url, headers=headers, follow_redirects=True)
    
    # Process the content
    processor = HtmlProcessor(normalized_url)
    readable_content = processor.process_html(body)
    print(readable_content)

def search_term(term):
    client = HttpClient()
    
    # Prepare search URL
    search_url = f"https://duckduckgo.com/?q={quote_plus(term)}" 
    
    print(f"Searching for: {term}")
    print(f"Using search URL: {search_url}")
    
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    _, body = client.make_request(search_url, headers=headers)
    
    # Extract and display search results
    processor = HtmlProcessor(search_url)
    readable_content = processor.process_html(body)
    print(f"Search results for '{term}':")
    print(readable_content)

# Main entry point
def main():
    parser = argparse.ArgumentParser(
        description='Web request CLI tool without using HTTP libraries'
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Make an HTTP request to the specified URL')
    group.add_argument('-s', '--search', help='Search the term using a search engine')
    group.add_argument('--clear-cache', action='store_true', help='Clear the cache')
    
    args = parser.parse_args()
    
    if args.clear_cache:
        import shutil
        if os.path.exists(CACHE_DIR):
            shutil.rmtree(CACHE_DIR)
            os.makedirs(CACHE_DIR)
        print("Cache cleared successfully.")
    elif args.url:
        make_url_request(args.url)
    elif args.search:
        search_term(args.search)

if __name__ == "__main__":
    main()