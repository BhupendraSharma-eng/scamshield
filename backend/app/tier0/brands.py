"""Brand and domain data used by the Tier-0 URL rules.

Domains in ``BRANDS`` are maintained as lower-case DNS names.  Most are
registrable domains; a few service-specific official hosts are retained where
that is the public address users are expected to recognise.
"""

from __future__ import annotations

import re


BRANDS: dict[str, dict] = {
    "sbi": {"name": "SBI", "domains": ["onlinesbi.sbi", "sbi.co.in", "sbi"], "aliases": ["sbi", "state bank", "yono"]},
    "hdfc": {"name": "HDFC Bank", "domains": ["hdfcbank.com", "hdfc.bank.in"], "aliases": ["hdfc", "hdfc bank"]},
    "icici": {"name": "ICICI Bank", "domains": ["icicibank.com"], "aliases": ["icici", "icici bank"]},
    "axis": {"name": "Axis Bank", "domains": ["axisbank.com"], "aliases": ["axis", "axis bank"]},
    "kotak": {"name": "Kotak Mahindra Bank", "domains": ["kotak.com"], "aliases": ["kotak", "kotak bank"]},
    "pnb": {"name": "Punjab National Bank", "domains": ["pnbindia.in"], "aliases": ["pnb", "punjab national bank"]},
    "bob": {"name": "Bank of Baroda", "domains": ["bankofbaroda.in"], "aliases": ["bank of baroda", "bob"]},
    "paytm": {"name": "Paytm", "domains": ["paytm.com"], "aliases": ["paytm"]},
    "phonepe": {"name": "PhonePe", "domains": ["phonepe.com"], "aliases": ["phonepe", "phone pe"]},
    "gpay": {"name": "Google Pay", "domains": ["pay.google.com"], "aliases": ["google pay", "gpay"]},
    "bhim": {"name": "BHIM / NPCI", "domains": ["bhimupi.org.in", "npci.org.in"], "aliases": ["bhim", "bhim upi", "npci"]},
    "amazon": {"name": "Amazon", "domains": ["amazon.in", "amazon.com"], "aliases": ["amazon"]},
    "flipkart": {"name": "Flipkart", "domains": ["flipkart.com"], "aliases": ["flipkart"]},
    "myntra": {"name": "Myntra", "domains": ["myntra.com"], "aliases": ["myntra"]},
    "meesho": {"name": "Meesho", "domains": ["meesho.com"], "aliases": ["meesho"]},
    "irctc": {"name": "IRCTC", "domains": ["irctc.co.in"], "aliases": ["irctc", "rail connect"]},
    "indiapost": {"name": "India Post", "domains": ["indiapost.gov.in"], "aliases": ["india post", "indiapost", "post office"]},
    "bluedart": {"name": "Blue Dart", "domains": ["bluedart.com"], "aliases": ["blue dart", "bluedart"]},
    "delhivery": {"name": "Delhivery", "domains": ["delhivery.com"], "aliases": ["delhivery"]},
    "dhl": {"name": "DHL", "domains": ["dhl.com"], "aliases": ["dhl"]},
    "fedex": {"name": "FedEx", "domains": ["fedex.com"], "aliases": ["fedex"]},
    "incometax": {"name": "Income Tax Department", "domains": ["incometax.gov.in"], "aliases": ["income tax", "incometax", "e filing"]},
    "uidai": {"name": "UIDAI / Aadhaar", "domains": ["uidai.gov.in"], "aliases": ["uidai", "aadhaar", "aadhar"]},
    "epfo": {"name": "EPFO", "domains": ["epfindia.gov.in"], "aliases": ["epfo", "epf", "provident fund"]},
    "parivahan": {"name": "Parivahan / e-Challan", "domains": ["parivahan.gov.in"], "aliases": ["parivahan", "echallan", "e-challan"]},
    "uppcl": {"name": "UPPCL", "domains": ["uppcl.org", "uppclonline.com"], "aliases": ["uppcl"]},
    "cbse": {"name": "CBSE", "domains": ["cbse.gov.in", "cbse.nic.in"], "aliases": ["cbse"]},
    "ignou": {"name": "IGNOU", "domains": ["ignou.ac.in"], "aliases": ["ignou"]},
    "nsp": {"name": "National Scholarship Portal", "domains": ["scholarships.gov.in"], "aliases": ["national-scholarship", "nsp scholarship", "national scholarship"]},
    "du": {"name": "Delhi University", "domains": ["du.ac.in"], "aliases": ["delhi-univ", "delhi university"]},
    "jio": {"name": "Jio", "domains": ["jio.com"], "aliases": ["jio", "reliance jio"]},
    "airtel": {"name": "Airtel", "domains": ["airtel.in"], "aliases": ["airtel"]},
    "vi": {"name": "Vi", "domains": ["myvi.in"], "aliases": ["vodafone idea", "myvi", "vi"]},
    "bsnl": {"name": "BSNL", "domains": ["bsnl.co.in"], "aliases": ["bsnl"]},
    "bescom": {"name": "BESCOM", "domains": ["karnataka.gov.in"], "aliases": ["bescom", "electricity bill"]},
    "mahadiscom": {"name": "MSEDCL / MahaDiscom", "domains": ["mahadiscom.in"], "aliases": ["mahadiscom", "msedcl", "mahavitaran"]},
    "tatapower": {"name": "Tata Power", "domains": ["tatapower.com"], "aliases": ["tata power", "tatapower"]},
    "netflix": {"name": "Netflix", "domains": ["netflix.com"], "aliases": ["netflix"]},
    "microsoft": {"name": "Microsoft", "domains": ["microsoft.com", "live.com", "office.com", "outlook.com"], "aliases": ["microsoft", "office 365", "outlook"]},
    "apple": {"name": "Apple", "domains": ["apple.com", "icloud.com"], "aliases": ["apple", "icloud", "apple id"]},
    "google": {"name": "Google", "domains": ["google.com", "google.co.in"], "aliases": ["google", "gmail"]},
    "paypal": {"name": "PayPal", "domains": ["paypal.com", "paypal.in"], "aliases": ["paypal", "pay pal"]},
    "whatsapp": {"name": "WhatsApp", "domains": ["whatsapp.com", "wa.me"], "aliases": ["whatsapp", "whats app"]},
    "instagram": {"name": "Instagram", "domains": ["instagram.com"], "aliases": ["instagram", "insta"]},
    "facebook": {"name": "Facebook", "domains": ["facebook.com", "fb.com"], "aliases": ["facebook", "meta"]},
    "linkedin": {"name": "LinkedIn", "domains": ["linkedin.com"], "aliases": ["linkedin", "linked in"]},
}


# A compact, bundled allowlist keeps the analyzer deterministic and offline.
# It intentionally contains registrable domains (not arbitrary URL prefixes).
_POPULAR_DOMAINS = {
    "adobe.com", "airbnb.com", "alibaba.com", "aliexpress.com", "ampproject.org",
    "archive.org", "asana.com", "bbc.com", "bbc.co.uk", "bing.com", "bitbucket.org",
    "booking.com", "britannica.com", "canva.com", "cbse.gov.in", "cdc.gov", "chase.com",
    "chatgpt.com", "cisco.com", "cloudflare.com", "cnn.com", "codepen.io", "coursera.org",
    "cricbuzz.com", "dailymotion.com", "debian.org", "digilocker.gov.in", "discord.com",
    "docker.com", "doi.org", "dropbox.com", "duckduckgo.com", "ebay.com", "economist.com",
    "edx.org", "elastic.co", "espn.com", "etsy.com", "europa.eu", "eventbrite.com",
    "evernote.com", "fast.com", "figma.com", "firebase.google.com", "forbes.com",
    "freepik.com", "geeksforgeeks.org", "git-scm.com", "github.com", "gitlab.com",
    "gnu.org", "godaddy.com", "goodreads.com", "grammarly.com", "healthline.com",
    "hindustantimes.com", "hostinger.com", "hotstar.com", "ibm.com", "icann.org",
    "ieee.org", "ietf.org", "imdb.com", "india.gov.in", "indiatimes.com", "indeed.com",
    "instructure.com", "intel.com", "investopedia.com", "irs.gov", "isro.gov.in",
    "jabong.com", "javatpoint.com", "jetbrains.com", "jstor.org", "kaggle.com",
    "khanacademy.org", "leetcode.com", "licindia.in", "linktr.ee", "linux.org",
    "makemytrip.com", "medium.com", "mit.edu", "mozilla.org", "msn.com", "nasa.gov",
    "nature.com", "naukri.com", "nbcnews.com", "ndtv.com", "netlify.com", "nih.gov",
    "npmjs.com", "nytimes.com", "okta.com", "openai.com", "oracle.com", "ox.ac.uk",
    "pexels.com", "pinterest.com", "postgresql.org", "python.org", "quora.com",
    "reddit.com", "researchgate.net", "reuters.com", "salesforce.com", "samsung.com",
    "sciencedirect.com", "shopify.com", "slack.com", "snapdeal.com", "soundcloud.com",
    "spotify.com", "springer.com", "stackoverflow.com", "stackexchange.com", "stanford.edu",
    "stripe.com", "swiggy.com", "telegram.org", "theguardian.com", "thehindu.com",
    "timesofindia.com", "trello.com", "tripadvisor.com", "tumblr.com", "twitch.tv",
    "twitter.com", "ubuntu.com", "udemy.com", "un.org", "unicef.org", "unsplash.com",
    "upwork.com", "vercel.com", "vimeo.com", "w3.org", "weather.com", "webex.com",
    "who.int", "wikipedia.org", "wikimedia.org", "wordpress.com", "worldbank.org",
    "x.com", "yahoo.com", "yelp.com", "youtube.com", "zendesk.com", "zomato.com",
    "zoom.us",
}

SAFE_DOMAINS: frozenset[str] = frozenset(
    _POPULAR_DOMAINS
    | {
        domain
        for brand in BRANDS.values()
        for domain in brand["domains"]
    }
)


def brand_for_domain(registered_domain: str) -> str | None:
    """Return the owner of an exact official domain, if one is registered."""

    domain = registered_domain.lower().rstrip(".")
    for key, brand in BRANDS.items():
        if domain in brand["domains"]:
            return key
    return None


def brands_mentioned(text: str) -> list[str]:
    """Find brand aliases as whole words, preserving registry order."""

    lowered = text.lower()
    found: list[str] = []
    for key, brand in BRANDS.items():
        if any(
            re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered)
            for alias in brand["aliases"]
        ):
            found.append(key)
    return found
