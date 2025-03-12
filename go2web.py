#!/usr/bin/env python3
import argparse
import socket
import ssl
import re
import os
import json
import time
from urllib.parse import urlparse, urlencode, quote_plus

# Constants
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".go2web_cache")
CACHE_EXPIRY = 3600  # Cache expiry in seconds (1 hour)

# HTML tag stripping regex
HTML_TAG_PATTERN = re.compile(r'<[^>]+>')

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
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({
                'headers': headers,
                'content': content
            }, f)

# HTTP client
class HttpClient:
    def __init__(self):
        self.cache = HttpCache()
    
    def make_request(self, url, headers=None, follow_redirects=True, accept=None):
        # Check cache first
        cached_headers, cached_content = self.cache.get(url)
        if cached_content:
            return cached_headers, cached_content
        
        # Parse URL
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else "/"
        
        if parsed_url.query:
            path += "?" + parsed_url.query
        
        # Default port
        port = 443 if parsed_url.scheme == "https" else 80
        
        # Override port if specified in URL
        if ":" in host:
            host, port_str = host.split(":")
            port = int(port_str)
        
        # Prepare custom headers
        if headers is None:
            headers = {}
        
        if 'User-Agent' not in headers:
            headers['User-Agent'] = USER_AGENT
        
        if 'Host' not in headers:
            headers['Host'] = host
        
        if accept and 'Accept' not in headers:
            headers['Accept'] = accept
        
        # Create request
        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        
        for header_name, header_value in headers.items():
            request += f"{header_name}: {header_value}\r\n"
        
        request += "Connection: close\r\n\r\n"
        
        # Connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            if parsed_url.scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.sendall(request.encode())
            
            # Receive the response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            # Parse the response
            response_str = response.decode('utf-8', errors='replace')
            
            # Split headers and body
            header_end = response_str.find("\r\n\r\n")
            if header_end == -1:
                raise Exception("Invalid HTTP response")
            
            headers_str = response_str[:header_end]
            body = response_str[header_end + 4:]
            
            # Parse headers
            headers_lines = headers_str.split("\r\n")
            status_line = headers_lines[0]
            headers = {}
            
            for line in headers_lines[1:]:
                if ": " in line:
                    name, value = line.split(": ", 1)
                    headers[name.lower()] = value
            
            # Check for redirect
            status_code = int(status_line.split(" ")[1])
            if follow_redirects and status_code in (301, 302, 303, 307, 308) and 'location' in headers:
                redirect_url = headers['location']
                
                # Handle relative URLs
                if redirect_url.startswith('/'):
                    redirect_url = f"{parsed_url.scheme}://{host}{redirect_url}"
                
                print(f"Redirecting to: {redirect_url}")
                return self.make_request(redirect_url, headers, follow_redirects, accept)
            
            # Check for transfer-encoding: chunked
            if headers.get('transfer-encoding') == 'chunked':
                body = self._decode_chunked(body)
            
            # Handle content encodings if needed (future improvement)
            
            # Content negotiation - check Content-Type
            content_type = headers.get('content-type', '')
            
            # Cache the response
            self.cache.set(url, headers, body)
            
            return headers, body
        
        finally:
            sock.close()
    
    def _decode_chunked(self, body):
        # Simplified chunked decoding
        result = ""
        remaining = body
        
        while remaining:
            # Find the chunk size line
            chunk_size_end = remaining.find("\r\n")
            if chunk_size_end == -1:
                break
            
            # Parse chunk size (hex)
            chunk_size_line = remaining[:chunk_size_end]
            chunk_size = int(chunk_size_line.split(";")[0], 16)
            
            # End of chunks
            if chunk_size == 0:
                break
            
            # Extract chunk data
            chunk_start = chunk_size_end + 2
            chunk_end = chunk_start + chunk_size
            
            # Check if we have the complete chunk
            if len(remaining) < chunk_end + 2:
                break
            
            # Add chunk data to result
            result += remaining[chunk_start:chunk_end]
            
            # Move to next chunk
            remaining = remaining[chunk_end + 2:]
        
        return result

# Content processing
def strip_html_tags(html):
    """Remove HTML tags from text"""
    # First, clean up some common entities
    text = html.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    
    # Then remove all tags
    text = HTML_TAG_PATTERN.sub('', text)
    
    # Clean up whitespace
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        line = line.strip()
        if line:
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def format_json(json_str):
    """Format JSON content for readability"""
    try:
        parsed = json.loads(json_str)
        return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        return json_str

def extract_search_results(html):
    """Extract search results from Google HTML"""
    results = []
    
    # Very simple extraction of search results - this is a basic implementation
    # A proper implementation would use a dedicated HTML parser
    links = re.finditer(r'<a href="(https?://[^"]+)"[^>]*>(.*?)</a>', html)
    
    for match in links:
        url = match.group(1)
        title = strip_html_tags(match.group(2))
        
        # Skip Google's internal links
        if 'google.com' in url or not title.strip():
            continue
        
        results.append({
            'url': url,
            'title': title
        })
        
        if len(results) >= 10:
            break
    
    return results

# Main functions
def make_url_request(url):
    client = HttpClient()
    
    # Try different content types for content negotiation
    accept_headers = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8"
    
    headers, body = client.make_request(url, accept=accept_headers, follow_redirects=True)
    
    # Detect content type
    content_type = headers.get('content-type', '').lower()
    
    if 'application/json' in content_type:
        # Format JSON for better readability
        print(format_json(body))
    else:
        # Assume HTML or plain text
        print(strip_html_tags(body))

def search_term(term):
    client = HttpClient()
    
    # Prepare search URL
    search_url = f"https://www.google.com/search?q={quote_plus(term)}"
    
    headers = {
        'Accept': 'text/html',
        'User-Agent': USER_AGENT
    }
    
    _, body = client.make_request(search_url, headers=headers)
    
    # Extract and display search results
    results = extract_search_results(body)
    
    if not results:
        print("No search results found or could not parse results properly.")
        return
    
    print(f"Top {len(results)} results for '{term}':\n")
    
    for i, result in enumerate(results, 1):
        print(f"{i}. {result['title']}")
        print(f"   {result['url']}")
        print()

# Main entry point
def main():
    parser = argparse.ArgumentParser(
        description='Web request CLI tool without using HTTP libraries',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Make an HTTP request to the specified URL')
    group.add_argument('-s', '--search', help='Search the term using Google search engine')
    
    args = parser.parse_args()
    
    if args.url:
        make_url_request(args.url)
    elif args.search:
        search_term(args.search)

if __name__ == "__main__":
    main()