#!/usr/bin/env python3
"""
JavaScript Source Analyzer
--------------------------
Extracts hidden endpoints, API keys, and GraphQL queries from JS files.
Acts like 'LinkFinder' to find hidden routes in modern SPA apps (React/Vue/Angular).
"""

import re
import requests
from urllib.parse import urljoin
from typing import List, Dict, Set
from rich.console import Console

console = Console()


class JSAnalyzer:
    def __init__(self, target_url: str, js_urls: List[str], timeout: int = 10):
        self.target_url = target_url
        self.js_urls = js_urls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebPwnToolkit/2.0 (JS Analyzer)"

        # LinkFinder Regex (adapted)
        self.regex_str = r"""
          (?:"|')                               # Start newline delimiter
          (
            ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
            [^"'/]{1,}\.                        # Match a domainname (any character + dot)
            [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
            |
            ((?:/|\.\./|\./)                    # Start with /,../,./
            [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
            [^"'><,;|()]{1,})                   # Rest of the characters can't be
            |
            ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
            [a-zA-Z0-9_\-/]{1,}                 # Resource name
            \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
            [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-]{1,}                 # filename
            \.(?:php|asp|aspx|jsp|json|
                 action|html|js|txt|xml)        # . + extension
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
          )
          (?:"|')                               # End newline delimiter
        """
        self.pattern = re.compile(self.regex_str, re.VERBOSE)

        self.graphql_pattern = re.compile(r"(query|mutation)\s+[a-zA-Z0-9_]+\s*\{")

    def analyze(self) -> Dict[str, List[str]]:
        console.print(
            f"  [dim]→ Analyzing {len(self.js_urls)} JavaScript files for hidden routes...[/dim]"
        )

        endpoints: Set[str] = set()
        graphql: Set[str] = set()

        import concurrent.futures

        def _fetch_and_parse(js_url):
            try:
                resp = self.session.get(js_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    text = resp.text

                    # Find endpoints
                    matches = self.pattern.finditer(text)
                    for match in matches:
                        group = match.group(1)
                        if group and len(group) > 4:
                            endpoints.add(group)

                    # Find GraphQL
                    for match in self.graphql_pattern.finditer(text):
                        graphql.add(match.group(0) + " ... }")

            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(_fetch_and_parse, url) for url in self.js_urls]
            concurrent.futures.wait(futures)

        return {"endpoints": list(endpoints), "graphql_queries": list(graphql)}
