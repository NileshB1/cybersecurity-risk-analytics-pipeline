"""

Resolves inconsistent vendor name representations across the three data
sources into a single canonical form.

"""

import re
import logging
import sys
from typing import Dict, List, Optional, Tuple


# Logger Factory


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  —  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")

    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger



# Alias Registry


class VendorAliasRegistry:
    """
    Stores the curated vendor alias dictionary and provides fast lookup.

    The registry is built once at construction and cached. All lookups
    are performed on lowercased, stripped input to eliminate casing
    and whitespace differences.

    """

    # Keys: lowercase variants seen in the wild across NVD/KEV/breach data
    # Values : canonical display name used in PostgreSQL and the dashboard
    ALIAS_MAP: Dict[str, str] = {

        # Microsoft: some examples of variants
        "microsoft":"Microsoft",
        "microsoft corp":"Microsoft",
        "microsoft corporation": "Microsoft",
        "microsoft corp.": "Microsoft",
        "msft":"Microsoft",
        "microsoft windows": "Microsoft",
        "microsoft azure":"Microsoft",
        "microsoft office":"Microsoft",
        # Apple 
        "apple":"Apple",
        "apple inc":"Apple",
        "apple inc.":  "Apple",
        "apple computer":  "Apple",

        # Google / Alphabet 
        "google": "Google",
        "google llc": "Google",
        "alphabet": "Google",
        "alphabet inc": "Google",
        "alphabet inc.": "Google",
        "google inc":  "Google",
        "google inc.":"Google",

        # Apache 
        "apache":"Apache",
        "apache software foundation": "Apache",
        "the apache software foundation": "Apache",
        "apache foundation": "Apache",

        # Oracle 
        "oracle":"Oracle",
        "oracle corporation":"Oracle",
        "oracle corp": "Oracle",
        "oracle corp.": "Oracle",
        "sun microsystems":"Oracle",    # acquired by Oracle

        # Cisco
        "cisco":  "Cisco",
        "cisco systems": "Cisco",
        "cisco systems inc": "Cisco",
        "cisco systems, inc":"Cisco",
        "cisco systems, inc.":"Cisco",

        # Adobe 
        "adobe":"Adobe",
        "adobe inc": "Adobe",
        "adobe inc.":"Adobe",
        "adobe systems":"Adobe",
        "adobe systems incorporated":"Adobe",

        # Linux
        "linux": "Linux",
        "linux kernel": "Linux",
        "the linux foundation":"Linux",
        #VMware 
        "vmware":"VMware",
        "vmware inc": "VMware",
        "vmware inc.":"VMware",
        "broadcom":"Broadcom",   # acquired VMware

        #Fortinet
        "fortinet": "Fortinet",
        "fortinet inc":"Fortinet",
        "fortinet inc.":"Fortinet",

        # Ivanti (Pulse Secure) 
        "ivanti":  "Ivanti",
        "pulse secure":"Ivanti",
        "pulsesecure": "Ivanti",

        #Atlassian
        "atlassian":"Atlassian",
        "atlassian corporation":"Atlassian",

        # MOVEit/Progress 
        "progress": "Progress Software",
        "progress software": "Progress Software",
        "moveit":"Progress Software",

        # Palo Alto Networks
        "palo alto networks":"Palo Alto Networks",
        "palo alto": "Palo Alto Networks",

        #Citrix / Cloud Software Group
        "citrix": "Citrix",
        "citrix systems":"Citrix",
        "cloud software group":"Citrix",

        #F5
        "f5":"F5",
        "f5 networks":  "F5",
        "f5, inc":"F5",
        "f5 inc": "F5",

        # SolarWinds 
        "solarwinds":"SolarWinds",
        "solarwinds inc": "SolarWinds",

        # Zoho
        "zoho":"Zoho",
        "zoho corp":"Zoho",
        "zoho corporation": "Zoho",

        # Generic
        "n/a":  "Unknown",
        "unknown":"Unknown",
        "": "Unknown",
        "-": "Unknown",
        "other":"Unknown",
    }

    def __init__(self):
        # Build a lowercase-keyed version for fast O(1) lookup
        self._lookup: Dict[str, str] = {
            k.lower().strip(): v for k, v in self.ALIAS_MAP.items()
        }
        # Canonical names for substring matching
        self._canonicals: List[str] = sorted(
            set(self.ALIAS_MAP.values()),
            key=len,
            reverse=True
        )

    def exact_lookup(self, normalised_input: str) -> Optional[str]:
        """1: dictionary lookup on lowercase input."""
        return self._lookup.get(normalised_input)

    def substring_match(self, normalised_input: str) -> Optional[str]:
        """
        2 : Check if any canonical name appears inside the input,
        or the input appears inside a canonical name
        """
        for canonical in self._canonicals:
            canonical_lower = canonical.lower()
            if canonical_lower in normalised_input or normalised_input in canonical_lower:
                return canonical
        return None

    def canonical_names(self) -> List[str]:
        return list(self._canonicals)



# Normalisation Stats


class NormalisationStats:
    """
    tracks how many vendors were resolved at each lookup stage."""

    def __init__(self):
        self.exact_hits: int=0
        self.substring_hits: int = 0
        self.fallbacks: int=0
        self.nulls:int=0

    def summary(self) -> str:
        total = self.exact_hits + self.substring_hits + self.fallbacks + self.nulls
        return (
            f"VendorNormaliser — total={total:,}  "
            f"exact={self.exact_hits:,}  "
            f"substring={self.substring_hits:,}  "
            f"fallback(title-case)={self.fallbacks:,}  "
            f"null={self.nulls:,}"
        )
    def reset(self) -> None:
        self.exact_hits = self.substring_hits = self.fallbacks = self.nulls = 0



# Text Cleaner

class VendorTextCleaner:
    """
    Remove white spaces and Legal suffixes from vedor
    """

    # Legal suffixes to strip from the end of vendor names
    _SUFFIX_PATTERN = re.compile(
        r"""
        [,\s]+          # optional leading comma/space before the suffix
        (
            ltd\.?| limited | llc\.? | llp\.? |
            inc\.? | incorporated| corp\.? | corporation|gmbh\.?| ag\.? | s\.a\.? | b\.v\.? |
            plc\.? | co\.? | company| group|
            holdings? | international| technologies? | software|
            solutions? | services? | systems? | networks?
        )
        \.?$            # optional trailing dot before end of string
        """,
        re.IGNORECASE | re.VERBOSE
    )

    @classmethod
    def clean(cls, raw: str) -> str:
        """return a cleaned, lowercased vendor string ready for lookup
        """
        if not raw:
            return ""

        #Remove non-printable characters
        cleaned = "".join(c for c in raw if c.isprintable())

        #strip legal suffixes
        for _ in range(3):
            stripped = cls._SUFFIX_PATTERN.sub("", cleaned).strip()
            if stripped==cleaned:
                break
            cleaned = stripped
        # Collapse internal whitespace and lowercase
        cleaned=re.sub(r"\s+", " ", cleaned).strip().lower()
        return cleaned



# Vendor Normaliser


class VendorNormaliser:
    """
    Converts any vendor name string to a canonical form
    """

    UNKNOWN = "Unknown"

    def __init__(self):
        self.logger = configure_logger("VendorNormaliser")
        self._cleaner = VendorTextCleaner()
        self._registry = VendorAliasRegistry()
        self.stats= NormalisationStats()

    def normalise(self, raw_vendor: Optional[str]) -> str:
        """
        Main entry point. 
        """
        # Stage 0 — null guard
        if not raw_vendor or not str(raw_vendor).strip():
            self.stats.nulls += 1
            return self.UNKNOWN

        cleaned = self._cleaner.clean(str(raw_vendor))

        #1: exact alias lookup
        result = self._registry.exact_lookup(cleaned)
        if result:
            self.stats.exact_hits += 1
            self.logger.debug(f"Exact match: '{raw_vendor}' → '{result}'")
            return result

        #2 : substring match
        result = self._registry.substring_match(cleaned)
        if result:
            self.stats.substring_hits += 1
            self.logger.debug(f"Substring match: '{raw_vendor}' → '{result}'")
            return result

        #3: title-case fallback
        fallback = cleaned.title() if cleaned else self.UNKNOWN
        self.stats.fallbacks += 1
        self.logger.debug(f"Fallback (title-case): '{raw_vendor}' → '{fallback}'")
        return fallback

    def normalise_list(self, vendor_list: List[str]) -> List[str]:
        """
        Normalise a list of vendor names (used for NVD records that
        can have multiple vendors per CVE) and return deduplicated results
        """
        seen= set()
        results= []
        for vendor in vendor_list:
            normalised = self.normalise(vendor)
            
            if normalised not in seen:
                seen.add(normalised)
                results.append(normalised)
        return results

    def log_summary(self) -> None:
        """
        Log a statistics summary, call at the end of a transform run."""
        self.logger.info(self.stats.summary())

    def reset_stats(self) -> None:
        self.stats.reset()