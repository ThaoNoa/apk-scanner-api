import yara
import os
from typing import List, Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class YaraScanner:
    def __init__(self, rules_path: str = "app/yara_rules/malware_rules.yar"):
        self.rules_path = rules_path
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile YARA rules"""
        try:
            if os.path.exists(self.rules_path):
                self.rules = yara.compile(filepath=self.rules_path)
                logger.info(f"YARA rules compiled successfully from {self.rules_path}")
            else:
                logger.warning(f"YARA rules file not found: {self.rules_path}")
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self.rules = None

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file with YARA rules"""
        matches = []

        if not self.rules:
            logger.warning("YARA rules not compiled")
            return matches

        try:
            # Scan the file
            result = self.rules.match(file_path)

            for match in result:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": match.meta,
                    "strings": []
                }

                # Add matched strings
                for string in match.strings:
                    match_info["strings"].append({
                        "identifier": string.identifier,
                        "data": string.instances[0].matched_data.decode('utf-8',
                                                                        errors='ignore') if string.instances else ""
                    })

                matches.append(match_info)

        except Exception as e:
            logger.error(f"Error scanning file with YARA: {e}")

        return matches

    def scan_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan bytes data with YARA rules"""
        matches = []

        if not self.rules:
            logger.warning("YARA rules not compiled")
            return matches

        try:
            result = self.rules.match(data=data)

            for match in result:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": match.meta
                }
                matches.append(match_info)

        except Exception as e:
            logger.error(f"Error scanning bytes with YARA: {e}")

        return matches