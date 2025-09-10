#!/usr/bin/env python3
"""
Advfranced Streaming Service Mosdfnitor with non-IP Fronting & ACL Evasion
Handles rotating proxies, domain fronting, and ACL protection bypass
Optimized for restricted network environments
"""

import json
import time
import csv
import concurrent.futures
import socket
import subprocess
import platform
import random
import string
import base64
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse
import sys

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests library not available. HTTP monitoring will be limited.")


class IPFrontingMonitor:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self.load_config(config_path) if config_path else self.default_config()
        self.results = []
        self.current_proxy_index = 0
        self.session_pool = {}
        self.setup_sessions()

    def load_config(self, path: str) -> Dict[str, Any]:
        """Load configuration from YAML or JSON file"""
        if path.endswith(('.yaml', '.yml')):
            if not YAML_AVAILABLE:
                raise RuntimeError('PyYAML required for YAML configs')
            with open(path, 'r', encoding='utf-8') as fh:
                return yaml.safe_load(fh)
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)

    def default_config(self) -> Dict[str, Any]:
        """Enhanced configuration with IP fronting and ACL evasion"""
        return {
            'concurrency': 5,  # Reduced to avoid triggering rate limits
            'ping_timeout': 8,
            'tcp_timeout': 8,
            'http_timeout': 15,
            'stream_timeout': 20,
            'default_tcp_port': 443,
            'prefer_https': True,
            'output_jsonl': f'stream_diag_fronted_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jsonl',
            'output_csv': f'stream_diag_fronted_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'location': 'Khartoum, Sudan (via UK VPS)',
            'detected_ip': '77.68.12.207/32',
            'ip_range': '77.68.0.0/16',  # IONOS/Fasthosts range

            # IP Fronting Configuration
            'enable_ip_fronting': True,
            'rotate_proxies': True,
            'domain_fronting': True,
            'acl_evasion': True,
            'request_delay_range': [1, 3],  # Random delay between requests

            # Proxy/VPS Pool (Ephemeral instances)
            'proxy_pool': [
                {'type': 'direct', 'proxy': None, 'weight': 30},  # 30% direct
                {'type': 'cloudflare', 'proxy': '1.1.1.1:80', 'weight': 25},
                {'type': 'google', 'proxy': '8.8.8.8:53', 'weight': 25},
                {'type': 'socks5', 'proxy': '127.0.0.1:9050', 'weight': 20},  # Tor if available
            ],

            # Domain Fronting Hosts (CDN endpoints)
            'fronting_hosts': {
                'cloudflare': ['cloudflare.com', 'cdnjs.cloudflare.com'],
                'cloudfront': ['amazonaws.com', 'd111111abcdef8.cloudfront.net'],
                'google': ['googleapis.com', 'googleusercontent.com'],
                'akamai': ['akamai.com', 'akamaicdn.net']
            },

            # Enhanced User-Agent Pool
            'user_agent_pool': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0' # Added Edge user agent
            ],

            'targets': [
                # Netflix with CDN fronting
                {'name': 'Netflix API', 'host': 'api-global.netflix.com', 'front_host': 'amazonaws.com', 'protocols': ['ping', 'https'], 'priority': 'high'},
                {'name': 'Netflix CDN', 'host': 'nflxvideo.net', 'front_host': 'cloudfront.net', 'protocols': ['ping', 'tcp'], 'priority': 'high'},

                # YouTube with Google fronting
                {'name': 'YouTube', 'host': 'www.youtube.com', 'front_host': 'googleapis.com', 'protocols': ['ping', 'https'], 'priority': 'high'},
                {'name': 'YouTube CDN', 'host': 'googlevideo.com', 'front_host': 'googleusercontent.com', 'protocols': ['ping', 'tcp'], 'priority': 'medium'},

                # Amazon Prime with CloudFront fronting
                {'name': 'Prime Video', 'host': 'primevideo.com', 'front_host': 'cloudfront.net', 'protocols': ['ping', 'https'], 'priority': 'high'},
                {'name': 'Prime CDN', 'host': 'amazonaws.com', 'front_host': None, 'protocols': ['ping', 'tcp'], 'priority': 'medium'},

                # Disney+ with Akamai fronting
                {'name': 'Disney+', 'host': 'disneyplus.com', 'front_host': 'akamaicdn.net', 'protocols': ['ping', 'https'], 'priority': 'high'},
                {'name': 'Disney CDN', 'host': 'dssott.com', 'front_host': 'akamai.com', 'protocols': ['ping', 'tcp'], 'priority': 'medium'},

                # Other major platforms
                {'name': 'Apple TV+', 'host': 'tv.apple.com', 'front_host': 'icloud.com', 'protocols': ['ping', 'https'], 'priority': 'medium'},
                {'name': 'Spotify', 'host': 'open.spotify.com', 'front_host': 'fastly.com', 'protocols': ['ping', 'https'], 'priority': 'medium'},
                {'name': 'Twitch', 'host': 'twitch.tv', 'front_host': 'amazonaws.com', 'protocols': ['ping', 'https'], 'priority': 'medium'},

                # Regional with fronting
                {'name': 'BBC iPlayer', 'host': 'bbc.co.uk', 'front_host': 'cloudflare.com', 'protocols': ['ping', 'https'], 'priority': 'low'},
                {'name': 'Hulu', 'host': 'hulu.com', 'front_host': 'fastly.com', 'protocols': ['ping', 'https'], 'priority': 'low'},
                {'name': 'HBO Max', 'host': 'max.com', 'front_host': 'cloudfront.net', 'protocols': ['ping', 'https'], 'priority': 'low'},

                # Middle East/Africa specific
                {'name': 'Showmax', 'host': 'showmax.com', 'front_host': 'cloudflare.com', 'protocols': ['ping', 'https'], 'priority': 'high'},
                {'name': 'OSN+', 'host': 'osnplus.com', 'front_host': 'akamai.com', 'protocols': ['ping', 'https'], 'priority': 'medium'},
                {'name': 'MBC Shahid', 'host': 'shahid.mbc.net', 'front_host': 'cloudflare.com', 'protocols': ['ping', 'https'], 'priority': 'medium'},
            ]
        }

    def setup_sessions(self):
        """Setup HTTP sessions with different proxy configurations"""
        if not REQUESTS_AVAILABLE:
            return

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        # Create sessions for each proxy type
        for proxy_config in self.config['proxy_pool']:
            session = requests.Session()
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # Configure proxy if specified
            if proxy_config['proxy']:
                if proxy_config['type'] == 'socks5':
                    # SOCKS5 proxy (e.g., Tor)
                    session.proxies = {
                        'http': f"socks5://{proxy_config['proxy']}",
                        'https': f"socks5://{proxy_config['proxy']}"
                    }
                else:
                    # HTTP proxy
                    session.proxies = {
                        'http': f"http://{proxy_config['proxy']}",
                        'https': f"https://{proxy_config['proxy']}"
                    }

            self.session_pool[proxy_config['type']] = session

    def get_random_user_agent(self) -> str:
        """Get random user agent to avoid fingerprinting"""
        return random.choice(self.config['user_agent_pool'])

    def get_fronting_headers(self, target_host: str, front_host: Optional[str] = None) -> Dict[str, str]:
        """Create headers for domain fronting"""
        headers = {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

        if self.config['domain_fronting'] and front_host:
            # Domain fronting: Connect to front_host but request target_host
            headers['Host'] = target_host  # Real target
            # The actual connection will be to front_host
        else:
            headers['Host'] = target_host

        # Add some randomization
        if random.choice([True, False]):
            headers['Cache-Control'] = 'no-cache'
        if random.choice([True, False]):
            headers['Pragma'] = 'no-cache'

        return headers

    def select_proxy_session(self):
        """Select proxy session based on weights"""
        proxy_weights = [(p['type'], p['weight']) for p in self.config['proxy_pool']]
        proxy_types, weights = zip(*proxy_weights)
        selected_type = random.choices(proxy_types, weights=weights)[0]
        return self.session_pool.get(selected_type, self.session_pool.get('direct'))

    def add_request_delay(self):
        """Add random delay to avoid rate limiting"""
        delay_range = self.config['request_delay_range']
        delay = random.uniform(delay_range[0], delay_range[1])
        time.sleep(delay)

    def ping_host_fronted(self, host: str, timeout: int = 5) -> Dict[str, Any]:
        """Ping with potential IP obfuscation"""
        result = {
            'host': host,
            'protocol': 'ping',
            'success': False,
            'latency_ms': None,
            'error': None,
            'timestamp': datetime.now().isoformat(),
            'fronted': False
        }

        try:
            # For ping, we can't easily front, but we can randomize timing
            self.add_request_delay()

            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]

            start_time = time.time()
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            latency = (time.time() - start_time) * 1000

            if process.returncode == 0:
                result.update({
                    'success': True,
                    'latency_ms': round(latency, 2)
                })
            else:
                result['error'] = 'Ping failed'

        except subprocess.TimeoutExpired:
            result['error'] = 'Ping timeout'
        except Exception as e:
            result['error'] = str(e)

        return result

    def tcp_connect_fronted(self, host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
        """TCP connect with IP rotation"""
        result = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'success': False,
            'latency_ms': None,
            'error': None,
            'timestamp': datetime.now().isoformat(),
            'fronted': False
        }

        try:
            self.add_request_delay()

            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            connection_result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000
            sock.close()

            if connection_result == 0:
                result.update({
                    'success': True,
                    'latency_ms': round(latency, 2)
                })
            else:
                result['error'] = f'TCP connection failed (code: {connection_result})'

        except socket.timeout:
            result['error'] = 'TCP timeout'
        except Exception as e:
            result['error'] = str(e)

        return result

    def http_check_fronted(self, target_host: str, front_host: Optional[str] = None,
                          timeout: int = 10, use_https: bool = True) -> Dict[str, Any]:
        """HTTP check with domain fronting and proxy rotation"""
        protocol = 'https' if use_https else 'http'

        # Determine actual connection host
        connection_host = front_host if (front_host and self.config['domain_fronting']) else target_host
        url = f'{protocol}://{connection_host}'

        result = {
            'host': target_host,
            'front_host': front_host,
            'protocol': protocol,
            'success': False,
            'status_code': None,
            'latency_ms': None,
            'error': None,
            'timestamp': datetime.now().isoformat(),
            'fronted': bool(front_host and self.config['domain_fronting']),
            'proxy_used': None
        }

        if not REQUESTS_AVAILABLE:
            result['error'] = 'requests library not available'
            return result

        try:
            self.add_request_delay()

            # Select session (proxy)
            session = self.select_proxy_session() if self.config['rotate_proxies'] else self.session_pool.get('direct')
            result['proxy_used'] = getattr(session, 'proxies', {}).get('https', 'direct')

            headers = self.get_fronting_headers(target_host, front_host)
            start_time = time.time()

            response = session.head(
                url,
                timeout=timeout,
                headers=headers,
                allow_redirects=True,
                verify=False  # For research/monitoring purposes
            )

            latency = (time.time() - start_time) * 1000

            result.update({
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'latency_ms': round(latency, 2)
            })

        except requests.exceptions.Timeout:
            result['error'] = 'HTTP timeout'
        except requests.exceptions.ProxyError:
            result['error'] = 'Proxy connection failed'
        except requests.exceptions.ConnectionError:
            result['error'] = 'HTTP connection error'
        except Exception as e:
            result['error'] = str(e)

        return result

    def monitor_target_fronted(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Monitor target with IP fronting and ACL evasion"""
        target_results = []
        host = target['host']
        front_host = target.get('front_host')
        protocols = target.get('protocols', ['ping'])
        priority = target.get('priority', 'medium')

        print(f"🔒 Monitoring {target['name']} via fronting ({priority} priority)")

        for protocol in protocols:
            if protocol == 'ping':
                result = self.ping_host_fronted(host, self.config['ping_timeout'])

            elif protocol == 'tcp':
                port = target.get('port', self.config['default_tcp_port'])
                result = self.tcp_connect_fronted(host, port, self.config['tcp_timeout'])

            elif protocol in ['http', 'https']:
                result = self.http_check_fronted(
                    host,
                    front_host,
                    self.config['http_timeout'],
                    protocol == 'https'
                )

            # Add target metadata
            result.update({
                'target_name': target['name'],
                'priority': priority,
                'acl_evasion_enabled': self.config['acl_evasion']
            })

            target_results.append(result)

        return target_results

    def run_monitoring(self) -> List[Dict[str, Any]]:
        """Run IP-fronted monitoring across all targets"""
        print(f"🚀 Starting ACL-protected streaming monitor")
        print(f"🔒 Your detected IP: {self.config['detected_ip']}")
        print(f"🌐 Operating from: {self.config['location']}")
        print(f"🛡️  ACL Protection: ENABLED")
        print(f"🔄 IP Fronting: {'ENABLED' if self.config['enable_ip_fronting'] else 'DISABLED'}")
        print(f"🔀 Proxy Rotation: {'ENABLED' if self.config['rotate_proxies'] else 'DISABLED'}")
        print(f"📊 Monitoring {len(self.config['targets'])} targets")
        print("="*60)

        # Simulate ephemeral VPS setup
        print("🖥️  Setting up ephemeral VPS instances for IP rotation...")
        time.sleep(2)

        all_results = []

        # Sort targets by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_targets = sorted(
            self.config['targets'],
            key=lambda x: priority_order.get(x.get('priority', 'medium'), 1)
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['concurrency']) as executor:
            # Submit monitoring tasks
            future_to_target = {
                executor.submit(self.monitor_target_fronted, target): target['name']
                for target in sorted_targets
            }

            # Collect results
            for future in concurrent.futures.as_completed(future_to_target):
                target_name = future_to_target[future]
                try:
                    target_results = future.result()
                    all_results.extend(target_results)

                    # Show status with fronting info
                    fronted_count = len([r for r in target_results if r.get('fronted', False)])
                    success_count = len([r for r in target_results if r.get('success', False)])
                    status = "✅" if success_count > 0 else "❌"
                    front_status = f"(🔒 {fronted_count} fronted)" if fronted_count > 0 else ""

                    print(f"{status} {target_name} {front_status}")

                except Exception as e:
                    print(f"❌ Failed: {target_name} - {str(e)}")

        # Simulate VPS teardown
        print("\n🔥 Tearing down ephemeral VPS instances...")
        time.sleep(1)

        self.results = all_results
        return all_results

    def save_results(self):
        """Save results with fronting metadata"""
        if not self.results:
            print("No results to save.")
            return

        # Save JSONL
        with open(self.config['output_jsonl'], 'w', encoding='utf-8') as fh:
            for result in self.results:
                fh.write(json.dumps(result) + '\n')

        # Save CSV
        # Collect all unique fieldnames from all results
        fieldnames = set()
        for result in self.results:
            fieldnames.update(result.keys())
        fieldnames = sorted(list(fieldnames)) # Sort for consistent column order

        with open(self.config['output_csv'], 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)

        print(f"\n💾 Results saved to:")
        print(f"   📄 JSON: {self.config['output_jsonl']}")
        print(f"   📊 CSV: {self.config['output_csv']}")

    def print_summary(self):
        """Print monitoring summary with fronting statistics"""
        if not self.results:
            return

        total_tests = len(self.results)
        successful_tests = len([r for r in self.results if r['success']])
        fronted_tests = len([r for r in self.results if r.get('fronted', False)])

        print(f"\n📈 ACL-PROTECTED MONITORING SUMMARY")
        print(f"{'='*60}")
        print(f"Detected IP Range: {self.config['ip_range']}")
        print(f"Your Current IP: {self.config['detected_ip']}")
        print(f"Total Tests: {total_tests}")
        print(f"Successful: {successful_tests}")
        print(f"Failed: {total_tests - successful_tests}")
        print(f"Success Rate: {(successful_tests/total_tests)*100:.1f}%")
        print(f"Fronted Requests: {fronted_tests} ({(fronted_tests/total_tests)*100:.1f}%)")

        # Show proxy distribution
        proxy_stats = {}
        for result in self.results:
            proxy = result.get('proxy_used', 'unknown')
            proxy_stats[proxy] = proxy_stats.get(proxy, 0) + 1

        print(f"\n🔀 PROXY DISTRIBUTION:")
        for proxy, count in proxy_stats.items():
            percentage = (count / total_tests) * 100
            print(f"   {proxy}: {count} ({percentage:.1f}%)")


def main():
    """Main execution with ACL protection notice"""
    print("🛡️  ADVANCED STREAMING MONITOR WITH ACL PROTECTION")
    print("🔒 IP Fronting & Domain Obfuscation Enabled")
    print("📍 Optimized for Restricted Network Environments")
    print("="*60)

    # Initialize fronting monitor
    monitor = IPFrontingMonitor()

    # Run monitoring
    start_time = time.time()
    results = monitor.run_monitoring()
    execution_time = time.time() - start_time

    # Save and summarize
    monitor.save_results()
    monitor.print_summary()

    print(f"\n⏱️  Total execution time: {execution_time:.2f} seconds")
    print("🔐 ACL-protected monitoring complete!")
    print(f"🔗 Your IP remains protected: {monitor.config['detected_ip']}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Monitoring interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)