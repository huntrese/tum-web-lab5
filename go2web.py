#!/usr/bin/env python3
import argparse
import socket
import ssl
import re
import os
import json
import time
import html
from urllib.parse import urlparse, urlencode, quote_plus

# Constants
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
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
        
        if 'Accept' not in headers and accept:
            headers['Accept'] = accept
        
        # Add additional headers that help with Google and other sites
        if 'Accept-Language' not in headers:
            headers['Accept-Language'] = 'en-US,en;q=0.9'
        
        if 'Accept-Encoding' not in headers:
            headers['Accept-Encoding'] = 'identity'  # Avoid compression that we can't handle
            
        if 'Sec-Ch-Ua' not in headers:
            headers['Sec-Ch-Ua'] = '"Not A;Brand";v="99", "Chromium";v="120"'
            
        if 'Sec-Ch-Ua-Mobile' not in headers:
            headers['Sec-Ch-Ua-Mobile'] = '?0'
            
        if 'Sec-Ch-Ua-Platform' not in headers:
            headers['Sec-Ch-Ua-Platform'] = '"Windows"'
            
        if 'Sec-Fetch-Dest' not in headers:
            headers['Sec-Fetch-Dest'] = 'document'
            
        if 'Sec-Fetch-Mode' not in headers:
            headers['Sec-Fetch-Mode'] = 'navigate'
            
        if 'Sec-Fetch-Site' not in headers:
            headers['Sec-Fetch-Site'] = 'none'
            
        if 'Sec-Fetch-User' not in headers:
            headers['Sec-Fetch-User'] = '?1'
            
        if 'Upgrade-Insecure-Requests' not in headers:
            headers['Upgrade-Insecure-Requests'] = '1'
        
        # Create request
        request = f"GET {path} HTTP/1.1\r\n"
        
        for header_name, header_value in headers.items():
            request += f"{header_name}: {header_value}\r\n"
        
        request += "Connection: close\r\n\r\n"
        
        # Connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)  # Increased timeout
        
        try:
            if parsed_url.scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.sendall(request.encode())
            
            # Receive the response
            response = b""
            while True:
                try:
                    data = sock.recv(8192)  # Increased buffer size
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    # Handle timeout gracefully
                    print("Connection timed out, but received partial response.")
                    break
            
            # Make sure we have some data
            if not response:
                print(f"No response received from {url}")
                return {}, "No response received from server."
            
            try:
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
                
                # Print status information
                print(f"Status: {status_code}")
                
                if follow_redirects and status_code in (301, 302, 303, 307, 308) and 'location' in headers:
                    redirect_url = headers['location']
                    
                    # Handle relative URLs
                    if redirect_url.startswith('/'):
                        redirect_url = f"{parsed_url.scheme}://{host}{redirect_url}"
                    elif not redirect_url.startswith(('http://', 'https://')):
                        # Handle other relative URLs (without leading slash)
                        base_url = f"{parsed_url.scheme}://{host}"
                        if not path.endswith('/'):
                            # Remove the last part of the path
                            path = '/'.join(path.split('/')[:-1]) + '/'
                        base_url += path
                        redirect_url = f"{base_url}{redirect_url}"
                    
                    print(f"Redirecting to: {redirect_url}")
                    return self.make_request(redirect_url, headers, follow_redirects, accept)
                
                # Check for transfer-encoding: chunked
                if headers.get('transfer-encoding') == 'chunked':
                    body = self._decode_chunked(body)
                
                # Cache the response
                self.cache.set(url, headers, body)
                
                return headers, body
                
            except Exception as e:
                print(f"Error processing response: {e}")
                # Try to salvage what we can from the response
                return {}, response.decode('utf-8', errors='replace')
        
        except Exception as e:
            print(f"Connection error: {e}")
            return {}, f"Error connecting to {url}: {str(e)}"
        
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
            # Clean any non-hex characters
            hex_part = re.search(r'^([0-9a-fA-F]+)', chunk_size_line)
            if not hex_part:
                break
                
            try:
                chunk_size = int(hex_part.group(1), 16)
            except ValueError:
                break
            
            # End of chunks
            if chunk_size == 0:
                break
            
            # Extract chunk data
            chunk_start = chunk_size_end + 2
            chunk_end = chunk_start + chunk_size
            
            # Check if we have the complete chunk
            if len(remaining) < chunk_end + 2:
                # Add what we have and break
                result += remaining[chunk_start:]
                break
            
            # Add chunk data to result
            result += remaining[chunk_start:chunk_end]
            
            # Move to next chunk
            remaining = remaining[chunk_end + 2:]
        
        return result

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
        self.headings = []
        
    def process_html(self, html_content):
        # Simple state machine to parse HTML
        i = 0
        while i < len(html_content):
            # Check for comments
            if html_content[i:i+4] == '<!--' and not self.in_comment:
                self.in_comment = True
                i += 4
                continue
            
            if self.in_comment and html_content[i:i+3] == '-->':
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
                    break
                
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
                elif tag.startswith('h1') or tag.startswith('h2') or tag.startswith('h3'):
                    # Track headings for better structure
                    heading_level = int(tag[1])
                    self.current_text.append(f"\n{'#' * heading_level} ")
                elif tag in ['br', 'br/', 'br /']:
                    self.current_text.append("\n")
                elif tag in ['p', 'div']:
                    self.current_text.append("\n")
                elif tag == '/p' or tag == '/div':
                    self.current_text.append("\n")
                elif tag.startswith('a '):
                    # Extract href
                    href_match = re.search(r'href=["\'](.*?)["\']', tag)
                    if href_match:
                        href = href_match.group(1)
                        # Handle relative URLs
                        if href.startswith('/'):
                            # Absolute path relative to domain
                            parsed_url = urlparse(self.base_url)
                            href = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                        elif not href.startswith(('http://', 'https://')):
                            # Relative path
                            href = self.base_url + ('/' if not self.base_url.endswith('/') else '') + href
                        
                        self.current_link = href
                elif tag == '/a':
                    self.current_link = None
                elif tag.startswith('li'):
                    self.current_text.append("\n- ")
                elif tag == '/li':
                    self.current_text.append("\n")
                elif tag == 'title':
                    # Save title for display later
                    title_end = html_content.find('</title>', tag_end)
                    if title_end > tag_end:
                        title_text = html_content[tag_end+1:title_end].strip()
                        if title_text:
                            self.headings.append(f"Title: {title_text}")
                
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
        # Process text and add ANSI escape codes for clickable links
        result = []
        
        # First add any page title
        if self.headings:
            result.extend(self.headings)
            result.append("=" * 40)
        
        # Add processed text
        for text in self.output_buffer:
            # Decode HTML entities and clean up whitespace
            text = html.unescape(text)
            # Normalize whitespace but preserve intended line breaks
            text = re.sub(r'[ \t]+', ' ', text)
            text = re.sub(r'\n+', '\n', text)
            if text.strip():
                result.append(text)
        
        # Add links at the end
        if self.links:
            result.append("\n" + "=" * 40)
            result.append("Links:")
            for i, (text, url) in enumerate(self.links, 1):
                # Clean up link text
                text = html.unescape(text).strip()
                text = re.sub(r'\s+', ' ', text)
                if not text:
                    text = url
                
                # Use OSC 8 terminal escape sequence for clickable links
                # Format: \033]8;;URL\033\\TEXT\033]8;;\033\\
                clickable_link = f"\033]8;;{url}\033\\{text}\033]8;;\033\\"
                result.append(f"{i}. {clickable_link}")
        
        return '\n\n'.join(result)

def format_json(json_str):
    """Format JSON content for readability"""
    try:
        parsed = json.loads(json_str)
        return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        return json_str

# Main functions
def make_url_request(url):
    client = HttpClient()
    
    # Enhanced headers for better site compatibility
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0'
    }
    
    headers, body = client.make_request(url, headers=headers, follow_redirects=True)
    
    # Detect content type
    content_type = headers.get('content-type', '').lower()
    
    if 'application/json' in content_type:
        # Format JSON for better readability
        print(format_json(body))
    else:
        # Process HTML with improved processor
        processor = HtmlProcessor(url)
        readable_content = processor.process_html(body)
        print(readable_content)

def search_term(term):
    client = HttpClient()
    
    # Prepare search URL
    search_url = f"https://duckduckgo.com/?q={quote_plus(term)}"  # Switch to DuckDuckGo which is more friendly to scripts
    
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate', 
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1'
    }
    
    _, body = client.make_request(search_url, headers=headers)
    
    # Extract and display search results
    processor = HtmlProcessor(search_url)
    readable_content = processor.process_html(body)
    print(f"Search results for '{term}':\n")
    print(readable_content)

# Main entry point
def main():
    parser = argparse.ArgumentParser(
        description='Web request CLI tool without using HTTP libraries',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Make an HTTP request to the specified URL')
    group.add_argument('-s', '--search', help='Search the term using a search engine')
    
    args = parser.parse_args()
    
    if args.url:
        make_url_request(args.url)
    elif args.search:
        search_term(args.search)

if __name__ == "__main__":
    main()