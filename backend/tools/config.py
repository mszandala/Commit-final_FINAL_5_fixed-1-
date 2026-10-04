import re
import os
from functools import lru_cache
from pathlib import Path

# ============================== KONFIGURACJA ==============================
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

CALLS_DIR = DATA_DIR / "stock_market" / "cleaned_ECTs_dataset"
SEC_DIR = DATA_DIR / "stock_market" / "sec"
HR_DIR = DATA_DIR / "job_offers"
LEGAL_DIR = DATA_DIR / "legal_data"
IT_DIR = DATA_DIR / "it_data"
DB_DIR = str(DATA_DIR / "vector_db")

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION = "rag_" + EMBED_MODEL.split("/")[-1].replace(".", "-").lower()
OLD_COLLECTION = "earnings_calls"
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

MAX_CHARS, OVERLAP_PARAS, BATCH = 1200, 1, 256
SEC_USER_AGENT = os.environ.get("SEC_USER_AGENT", "")

COMPANY_RENAMES = {"branco": "banco-do-brasil"}

SEC_COMPANIES = {
    "Accenture": "ACN", "Adobe": "ADBE", "Allstate": "ALL", "Alphabet": "GOOGL",
    "Amazon": "AMZN", "AMD": "AMD", "Apple": "AAPL", "AXP": "AXP",
    "Bank of America": "BAC", "BKNG": "BKNG", "Cardinal Health": "CAH", "Cisco": "CSCO",
    "Citi": "C", "Costco": "COST", "Elevance Health": "ELV", "Ford": "F",
    "GM": "GM", "IBM": "IBM", "JPM": "JPM", "Lululemon": "LULU",
    "Marriott": "MAR", "Mastercard": "MA", "META": "META", "Microsoft": "MSFT",
    "Nike": "NKE", "Nvidia": "NVDA", "Oracle": "ORCL", "PAYPAL": "PYPL",
    "SalesForce": "CRM", "UnitedHealth": "UNH", "Walmart": "WMT", "Walt Disney": "DIS",
}

SEC_ITEMS = {
    "10-K": ["item_1", "item_1A", "item_7", "item_7A"],
    "10-Q": ["part_1_item_2", "part_1_item_3", "part_2_item_1A"],
}
SEC_MIN_CHARS = 300

ALIASES = {
    "google": "alphabet", "youtube": "alphabet", "facebook": "meta", "instagram": "meta",
    "jpmorgan": "jpm", "jp morgan": "jpm", "amex": "axp", "american express": "axp",
    "booking holdings": "bkng", "booking.com": "bkng", "general motors": "gm",
    "citigroup": "citi", "disney": "walt-disney", "unitedhealth group": "unitedhealth",
    "elevance": "elevance-health", "anthem": "elevance-health", "bofa": "bank-of-america",
    "lvmh": "louis-vuitton", "siemens": "sie", "brookfield": "bam",
    "banco do brasil": "banco-do-brasil", "l'oreal": "loreal", "l’oréal": "loreal",
}

DOC_TYPES = ("earnings_call", "sec_filing")

@lru_cache(maxsize=1)
def get_model():
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer(EMBED_MODEL)
    model.max_seq_length = 512
    return model

@lru_cache(maxsize=1)
def get_client():
    import chromadb
    return chromadb.PersistentClient(path=DB_DIR)

@lru_cache(maxsize=1)
def get_collection():
    return get_client().get_or_create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

def norm_company(name):
    key = re.sub(r"[\s_]+", "-", name.strip().lower())
    return COMPANY_RENAMES.get(key, key)