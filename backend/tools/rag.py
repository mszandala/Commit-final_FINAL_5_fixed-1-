import argparse
import json
import re
import time
from backend.tools.config import *

def progress(iterable, desc):
    try:
        from tqdm import tqdm
        return tqdm(iterable, desc=desc)
    except ImportError:
        return iterable

def chunk_paragraphs(text, max_chars=MAX_CHARS, overlap=OVERLAP_PARAS):
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, cur = [], []
    for p in paras:
        parts = [p] if len(p) <= max_chars else re.split(r"(?<=[.!?])\s+", p)
        for part in parts:
            if cur and sum(len(x) for x in cur) + len(part) > max_chars:
                chunks.append("\n".join(cur))
                cur = cur[-overlap:] if overlap else []
            cur.append(part)
    if cur:
        chunks.append("\n".join(cur))
    return chunks

def call_meta(path):
    meta = {"company": norm_company(path.parent.name), "doc_type": "earnings_call"}
    parts = path.stem.split("_")
    if len(parts) >= 2 and parts[0].isdigit():
        q = re.sub(r"\D", "", parts[1])
        meta["year"] = int(parts[0])
        meta["quarter"] = int(q) if q else 0
        meta["period"] = f"{parts[0]}-Q{q}" if q else parts[0]
    return meta

def clean_sec_text(text):
    text = re.sub(r"•\s*\n", "• ", text)
    return re.sub(r"\n+", "\n\n", text)

def is_boilerplate(chunk):
    return chunk.lower().count("forward-looking") >= 2

def is_it_boilerplate(chunk):
    """Wyłapuje generyczne stopki konfiguracyjne i logi automatyczne."""
    stopwords = [
        "this document is generated automatically", 
        "do not reply to this email",
        "strictly confidential internal use only"
    ]
    chunk_low = chunk.lower()
    return any(word in chunk_low for word in stopwords)



def is_legal_boilerplate(chunk):
    """Wyłapuje puste strony i robocze nagłówki z dokumentów prawnych."""
    stopwords = [
        "this page intentionally left blank", 
        "draft version - not for distribution",
        "[signature page follows]"
    ]
    chunk_low = chunk.lower()
    return any(word in chunk_low for word in stopwords)

def is_hr_boilerplate(chunk):
    """Filtruje typowe formułki prawne i RODO, które zapychają bazę wektorową."""
    stopwords = [
        "equal opportunity employer", 
        "klauzula rodo", 
        "przetwarzanie danych osobowych",
        "without regard to race, color, religion"
    ]
    chunk_low = chunk.lower()
    return any(word in chunk_low for word in stopwords)



class Buffer:
    def __init__(self):
        self.ids, self.docs, self.texts, self.metas = [], [], [], []

    def add(self, id_, doc, text_to_embed, meta):
        self.ids.append(id_)
        self.docs.append(doc)
        self.texts.append(text_to_embed)
        self.metas.append(meta)
        if len(self.ids) >= BATCH:
            self.flush()

    def flush(self):
        if not self.ids:
            return
        emb = get_model().encode(
            self.texts, normalize_embeddings=True, batch_size=32, show_progress_bar=False
        ).tolist()
        get_collection().upsert(
            ids=self.ids, documents=self.docs, embeddings=emb, metadatas=self.metas
        )
        self.ids, self.docs, self.texts, self.metas = [], [], [], []

def index_calls(buf, limit):
    files = sorted(CALLS_DIR.glob("*/*.txt"))
    if limit: files = files[:limit]
    print(f"Transkrypcje: {len(files)} plików w {CALLS_DIR}")
    for path in progress(files, "transkrypcje"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(CALLS_DIR).as_posix()
        meta = call_meta(path)
        for i, chunk in enumerate(chunk_paragraphs(text)):
            buf.add(
                f"call/{rel}-{i}", chunk,
                f"{meta['company']} {meta.get('period', '')}\n{chunk}",
                {**meta, "source": rel, "chunk": i},
            )
    buf.flush()

def migrate_calls():
    old = get_client().get_collection(OLD_COLLECTION)
    new = get_collection()
    print(f"Migracja z '{OLD_COLLECTION}' ({old.count()} chunków)...")
    offset = 0
    while True:
        res = old.get(include=["documents", "metadatas", "embeddings"], limit=2000, offset=offset)
        if not res["ids"]:
            break
        metas = []
        for m in res["metadatas"]:
            m = dict(m)
            m["doc_type"] = "earnings_call"
            m["company"] = norm_company(m.get("company", ""))
            metas.append(m)
        new.upsert(
            ids=["call/" + i for i in res["ids"]],
            documents=res["documents"],
            embeddings=[[float(x) for x in e] for e in res["embeddings"]],
            metadatas=metas,
        )
        offset += len(res["ids"])
        print(f"  przeniesiono {offset}")

def load_cik_map():
    cache = DATA_DIR / "cik_map.json"
    if cache.exists():
        return json.loads(cache.read_text())
    if not SEC_USER_AGENT:
        raise RuntimeError("set enviromental variable SEC_USER_AGENT, np. "
                           "export SEC_USER_AGENT='First Name Last Name (email)'")
    import requests
    r = requests.get("https://www.sec.gov/files/company_tickers.json",
                     headers={"User-Agent": SEC_USER_AGENT}, timeout=60)
    r.raise_for_status()
    t2c = {v["ticker"]: str(v["cik_str"]) for v in r.json().values()}
    mapping = {t2c[t]: norm_company(folder) for folder, t in SEC_COMPANIES.items() if t in t2c}
    cache.write_text(json.dumps(mapping))
    return mapping

def index_sec(buf, limit):
    cik_map = load_cik_map()
    files = sorted(SEC_DIR.rglob("*.json"))
    if limit: files = files[:limit]
    print(f"Raports SEC: {len(files)} files JSON in {SEC_DIR}")
    unknown = set()
    for path in progress(files, "raports SEC"):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        form = d.get("filing_type")
        raw_cik = str(d.get("cik", ""))
        company = cik_map.get(str(int(raw_cik))) if raw_cik.isdigit() else None
        if form not in SEC_ITEMS:
            continue
        if company is None:
            unknown.add(d.get("company", raw_cik))
            continue
        period = d.get("period_of_report", "") or ""
        filing_date = d.get("filing_date", "") or ""
        year_src = period or filing_date
        year = int(year_src[:4]) if year_src[:4].isdigit() else 0
        for key in SEC_ITEMS[form]:
            text = d.get(key) or ""
            if len(text) < SEC_MIN_CHARS:
                continue
            for i, chunk in enumerate(chunk_paragraphs(clean_sec_text(text))):
                if is_boilerplate(chunk):
                    continue
                buf.add(
                    f"sec/{path.stem}/{key}-{i}", chunk,
                    f"{company} {form} {period} {key}\n{chunk}",
                    {"company": company, "doc_type": "sec_filing", "year": year,
                     "period": period, "form": form, "section": key,
                     "filing_date": filing_date, "source": path.name, "chunk": i},
                )
    buf.flush()
    if unknown:
        print("Skipped companies without CIK:", sorted(unknown)[:20])

def index_hr(buf, limit=None):
    files = sorted(HR_DIR.rglob("*.json"))
    if limit: 
        files = files[:limit]
    print(f"Dane HR: {len(files)} plików JSON w {HR_DIR}")

    for path in progress(files, "dane HR"):
        try:
            loaded_data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # Ujednolicenie: jeśli to lista obiektów, iteruj po niej. 
        # Jeśli to pojedynczy słownik, zawiń go w listę.
        records = loaded_data if isinstance(loaded_data, list) else [loaded_data]

        for idx, d in enumerate(records):
            if not isinstance(d, dict):
                continue
                
            company = d.get("company", "Unknown")
            doc_type = d.get("type", "job_offer")
            role = d.get("role", "")
            
            text_parts = [
                d.get("description", ""), 
                d.get("requirements", ""), 
                d.get("benefits", ""),
                f"Salary range: {d.get('salary_range', '')}" if d.get("salary_range") else "",
                f"Location: {d.get('country', '')}" if d.get("country") else ""
            ]
            full_text = "\n\n".join(filter(bool, text_parts))

            if len(full_text) < 100:
                continue

            for i, chunk in enumerate(chunk_paragraphs(full_text)):
                if is_hr_boilerplate(chunk):
                    continue
                
                embed_text = f"{company} {doc_type} {role}\n{chunk}"
                
                meta = {
                    "company": norm_company(company), 
                    "doc_type": doc_type, 
                    "role": role,
                    "department": d.get("department", "HR"),
                    "year": d.get("publication_year", 0),
                    "country": d.get("country", ""),
                    "source": path.name, 
                    "chunk": i
                }
                
                # Dodano 'idx' do identyfikatora, aby uniknąć nadpisywania chunków
                # w przypadku, gdy plik zawiera wiele ofert pracy.
                unique_id = f"hr/{path.stem}-rec{idx}-{i}"
                buf.add(unique_id, chunk, embed_text, meta)
                
    buf.flush()

def index_it(buf, limit=None):
    files = sorted(IT_DIR.rglob("*.json"))
    if limit: 
        files = files[:limit]
    print(f"Dane IT: {len(files)} plików JSON w {IT_DIR}")

    for path in progress(files, "dane IT"):
        try:
            loaded_data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # Obsługa zarówno płaskich słowników, jak i list słowników
        records = loaded_data if isinstance(loaded_data, list) else [loaded_data]

        for idx, d in enumerate(records):
            if not isinstance(d, dict):
                continue

            company = d.get("company", "Unknown")
            doc_type = d.get("type", "architecture_decision_record")
            title = d.get("title", "")
            
            text_parts = [
                d.get("context", ""), 
                d.get("decision", ""), 
                d.get("consequences", ""),
                d.get("action_items", "")
            ]
            full_text = "\n\n".join(filter(bool, text_parts))

            if len(full_text) < 100:
                continue

            for i, chunk in enumerate(chunk_paragraphs(full_text)):
                if is_it_boilerplate(chunk):
                    continue
                
                embed_text = f"{company} {doc_type} {title}\n{chunk}"
                meta = {
                    "company": norm_company(company), 
                    "doc_type": doc_type, 
                    "title": title,
                    "department": d.get("department", "IT"),
                    "source": path.name, 
                    "chunk": i
                }
                
                # Unikalne ID oparte na indeksie rekordu
                unique_id = f"it/{path.stem}-rec{idx}-{i}"
                buf.add(unique_id, chunk, embed_text, meta)
                
    buf.flush()


def index_legal(buf, limit=None):
    files = sorted(LEGAL_DIR.rglob("*.json"))
    if limit: 
        files = files[:limit]
    print(f"Dane Legal: {len(files)} plików JSON w {LEGAL_DIR}")

    for path in progress(files, "dane Prawne"):
        try:
            loaded_data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # Obsługa zarówno płaskich słowników, jak i list słowników
        records = loaded_data if isinstance(loaded_data, list) else [loaded_data]

        for idx, d in enumerate(records):
            if not isinstance(d, dict):
                continue

            company = d.get("company", "Unknown")
            doc_type = d.get("type", "compliance_policy")
            title = d.get("title", "")
            
            text_parts = [
                d.get("policy_text", ""), 
                d.get("action_items", "")
            ]
            full_text = "\n\n".join(filter(bool, text_parts))

            if len(full_text) < 100:
                continue

            for i, chunk in enumerate(chunk_paragraphs(full_text)):
                if is_legal_boilerplate(chunk):
                    continue
                
                # Zabezpieczenie na wypadek braku listy tagów
                tags_list = d.get("tags", [])
                tags = " ".join(tags_list) if isinstance(tags_list, list) else str(tags_list)
                
                embed_text = f"{company} {doc_type} {title} {tags}\n{chunk}"
                meta = {
                    "company": norm_company(company), 
                    "doc_type": doc_type, 
                    "title": title,
                    "department": d.get("department", "Legal"),
                    "source": path.name, 
                    "chunk": i
                }
                
                # Unikalne ID oparte na indeksie rekordu
                unique_id = f"legal/{path.stem}-rec{idx}-{i}"
                buf.add(unique_id, chunk, embed_text, meta)
                
    buf.flush()


DATA_SOURCES = {
    "calls": index_calls,
    "sec": index_sec,
    "hr": index_hr,
    "legal": index_legal,
    "it": index_it
}

def reset_collection():
    try:
        get_client().delete_collection(COLLECTION)
    except Exception:
        pass
    get_collection.cache_clear()
    (DATA_DIR / "companies.json").unlink(missing_ok=True)

def build(source="all", reset=False, migrate=False, limit=None):
    if reset:
        reset_collection()
    t0 = time.time()
    buf = Buffer()
    if source in ("all", "calls") and migrate:
        migrate_calls()

    sources_to_run = DATA_SOURCES.keys() if source == "all" else [source]
    
    for src in sources_to_run:
        if src in DATA_SOURCES and not (src == "calls" and migrate):
            parser_func = DATA_SOURCES[src]
            parser_func(buf, limit)

    print(f"Ready: {get_collection().count()} chunks in '{COLLECTION}' ({round(time.time() - t0)} s)")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Zbuduj bazę danych RAG")
    ap.add_argument("--source", choices=['all']+ list(DATA_SOURCES.keys()), default="all")
    ap.add_argument("--reset", action="store_true", help="usuń kolekcję przed budową")
    ap.add_argument("--migrate", action="store_true", help="kopiuj embeddingi ze starej bazy")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    build(args.source, args.reset, args.migrate, args.limit)