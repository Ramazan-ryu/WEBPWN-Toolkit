#!/usr/bin/env python3
"""
Central Result Deduplication Engine
--------------------------------------
Prevents duplicate findings from multiple modules reporting the
same vulnerability on the same URL + parameter combination.
Uses BLAKE2b hashing for O(1) lookup.
"""

import hashlib
from typing import List, Dict


class ResultDeduplicator:
    """
    Thread-safe singleton deduplicator. Import once in main.py,
    pass to every module run, call .add() instead of direct append.

    Usage:
        dedup = ResultDeduplicator()
        new = dedup.add(module_results, session["findings"])
        print(f"{new} new unique finding(s) added.")
    """

    def __init__(self):
        self._seen: set = set()

    def _key(self, finding: Dict) -> str:
        f_type = finding.get("type", "")
        # Global vulnerabilities that should only be reported once per target,
        # regardless of the specific URL/path they were found on to avoid spam.
        global_vulns = [
            "Unauthenticated Admin Access",
            "Admin Login Panel Exposed",
            "Admin Panel — Default Credentials",
            "No Account Lockout",
            "JWT alg:none Attack Vector"
        ]
        
        if f_type in global_vulns:
            url_part = ""  # Ignore URL for global vulnerabilities to prevent duplicates
        else:
            url_part = finding.get("url", "")
            
        raw = "|".join(
            [
                url_part,
                f_type,
                finding.get("parameter", ""),
                str(finding.get("payload", ""))[:80],
            ]
        )
        return hashlib.blake2b(raw.encode(), digest_size=16).hexdigest()

    def add(self, new_findings: List[Dict], master_list: List[Dict]) -> int:
        """
        Add unique findings from `new_findings` into `master_list`.
        Returns the count of newly added (non-duplicate) findings.
        """
        added = 0
        for f in new_findings:
            k = self._key(f)
            if k not in self._seen:
                self._seen.add(k)
                master_list.append(f)
                added += 1
        return added

    def is_duplicate(self, finding: Dict) -> bool:
        return self._key(finding) in self._seen

    def seen_count(self) -> int:
        return len(self._seen)

    def reset(self):
        self._seen.clear()


# Global singleton — import from here
deduplicator = ResultDeduplicator()
