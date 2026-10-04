import argparse
import difflib
import json
import math
import re
from backend.tools.config import *

_COMPANIES = None

def load_companies():
    global _COMPANIES
    if _COMPANIES is not None:
        return _COMPANIES
    col = get_collection()
    n = col.count()
    cache = DATA_DIR / "companies.json"
    if cache.exists():
        data = json.loads(cache.read_text())
        if data.get("count") == n and data.get("collection") == COLLECTION:
            _COMPANIES = data["companies"]
            return _COMPANIES
    found, offset = set(), 0
    while True:
        res = col.get(include=["metadatas"], limit=5000, offset=offset)
        if not res["ids"]:
            break
        found.update(m["company"] for m in res["metadatas"] if "company" in m)
        offset += len(res["ids"])
    _COMPANIES = sorted(found)
    cache.write_text(json.dumps({"count": n, "collection": COLLECTION, "companies": _COMPANIES}))
    return _COMPANIES

def resolve_company(name):
    companies = load_companies()
    key = norm_company(name)
    key = norm_company(ALIASES.get(key.replace("-", " "), key))
    if key in companies:
        return key
    sub = [c for c in companies if key in c or c in key]
    if sub:
        return min(sub, key=len)
    close = difflib.get_close_matches(key, companies, n=1, cutoff=0.6)
    return close[0] if close else None

def _word(s):
    return rf"(?<![A-Za-z0-9]){re.escape(s)}(?![A-Za-z0-9])"

_ORDINALS = {"first": 1, "second": 2, "third": 3, "fourth": 4}

def detect_filters(question):
    companies, q_low = load_companies(), question.lower()
    found = []
    for c in companies:
        if len(c) <= 3:
            hit = re.search(_word(c.upper()), question)
        else:
            hit = re.search(_word(c.replace("-", " ")), q_low)
        if hit:
            found.append(c)
    for alias, target in ALIASES.items():
        if target in companies and target not in found and re.search(_word(alias), q_low):
            found.append(target)
    years = sorted({int(y) for y in re.findall(r"\b(20[12]\d)\b", question)})
    quarters = {int(q) for q in re.findall(r"\bq([1-4])\b", q_low)}
    quarters |= {_ORDINALS[w] for w in re.findall(r"\b(first|second|third|fourth) quarter\b", q_low)}
    return {"companies": found, "years": years, "quarters": sorted(quarters)}

def build_where(company=None, years=None, quarters=None, doc_type=None, department=None):
    def one_or_in(field, values):
        return {field: values[0]} if len(values) == 1 else {field: {"$in": list(values)}}

    conds = []
    if company:
        conds.append({"company": company})
    if doc_type:
        conds.append({"doc_type": doc_type})
    if department:
        conds.append({"department": department})
    if years:
        conds.append(one_or_in("year", years))
    if quarters:
        conds.append(one_or_in("quarter", quarters))
    
    if not conds:
        return None
    return conds[0] if len(conds) == 1 else {"$and": conds}

def retrieve(query, k=6, company=None, years=None, quarters=None, doc_type=None, department=None):
    col = get_collection()
    q = get_model().encode([QUERY_PREFIX + query], normalize_embeddings=True).tolist()
    
    where = build_where(company, years, quarters, doc_type, department)
    res = col.query(query_embeddings=q, n_results=k, where=where)
    
    hits = list(zip(res["documents"][0], res["metadatas"][0], res["distances"][0]))
    return hits

def gather(question, k=6, company=None, year=None, quarter=None, doc_type=None, department=None, auto=True):
    det = detect_filters(question) if auto else {"companies": [], "years": [], "quarters": []}
    if company:
        resolved = resolve_company(company)
        companies = [resolved] if resolved else []
    else:
        companies = det["companies"]
        
    years = [year] if year else det["years"]
    quarters = [quarter] if quarter else det["quarters"]
    applied = {"companies": companies, "years": years, "quarters": quarters, "doc_type": doc_type, "department": department}

    if len(companies) <= 1:
        hits = retrieve(question, k, companies[0] if companies else None, years, quarters, doc_type, department)
    else:
        per = max(2, k // len(companies))
        hits = []
        for c in companies:
            hits += retrieve(question, per, c, years, quarters, doc_type, department)
            
        hits.sort(key=lambda h: h[2]) # Sortowanie globalne po odległości dla wielu firm
        hits = hits[:k]
        
    return hits, applied

def format_sources(hits):
    lines = []
    for n, (_, m, dist) in enumerate(hits, 1):
        doc_type = m.get("doc_type", "unknown")
        comp = m.get("company", "Unknown")
        
        # Uniwersalne formatowanie w oparciu o metadane
        if doc_type == "sec_filing":
            what = f"SEC {m.get('form', '')} {m.get('period', '')} {m.get('section', '')}"
        elif doc_type == "earnings_call":
            what = f"Earnings Call {m.get('period', '')}"
        elif doc_type == "job_offer":
            what = f"HR Job Offer | {m.get('role', '')}"
        else:
            # Fallback dla IT (ADR) oraz Legal (Policy)
            dept = m.get("department", "General")
            title = m.get("title", doc_type)
            what = f"{dept} | {title}"
            
        lines.append(f"[{n}] {comp} | {what} | {m.get('source', '')} (dist={dist:.3f})")
    return "\n".join(lines)

def run_retrieve(args):
    hits, applied = gather(
        args.question, args.k, args.company, args.year, args.quarter, args.doc_type, args.department, not args.no_auto
    )
    print("Zastosowane filtry:", applied, "\n")
    if not hits:
        print("Nie znaleziono pasujących fragmentów w bazie.")
        return

    for doc, m, dist in hits:
        # Dynamiczne tagowanie bloku tekstu
        tag = m.get('department', m.get('doc_type', 'unknown')).upper()
        print(f"--- [{tag}] {m.get('company', '')} (dist={dist:.3f})")
        print(doc[:400].replace("\n", " ") + "...\n")
        
    print("Źródła:\n" + format_sources(hits))

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Wyszukiwanie kontekstu z bazy RAG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("search", help="Szukaj informacji na podstawie zapytania")
    p.add_argument("question")
    p.add_argument("-k", type=int, default=6)
    p.add_argument("--company")
    p.add_argument("--year", type=int)
    p.add_argument("--quarter", type=int)
    p.add_argument("--doc-type", dest="doc_type")
    p.add_argument("--department", help="Filtruj po dziale (np. HR, IT, Legal)")
    p.add_argument("--no-auto", action="store_true", help="nie wykrywaj filtrów z pytania")

    sub.add_parser("companies", help="lista spółek w bazie")

    args = ap.parse_args()
    if args.cmd == "search":
        run_retrieve(args)
    elif args.cmd == "companies":
        companies = load_companies()
        print(len(companies), "spółek:", ", ".join(companies))