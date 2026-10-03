import argparse
import difflib
import json
import re
from pathlib import Path

from backend.tools.rag import collection, model, norm_company, QUERY_PREFIX

CACHE = Path(__file__).resolve().parents[1] / "data" / "companies.json"


# ---------- spółki: odczyt partiami + cache ----------

def all_metadatas(batch=5000):
    metas, offset = [], 0
    while True:
        res = collection.get(include=["metadatas"], limit=batch, offset=offset)
        got = res["metadatas"]
        if not got:
            break
        metas.extend(got)
        offset += len(got)
    return metas


_COMPANIES = None

def load_companies():
    """Lista spółek z bazy; cache na dysku, odświeżany gdy zmieni się liczba chunków."""
    global _COMPANIES
    if _COMPANIES is not None:
        return _COMPANIES
    n = collection.count()
    if CACHE.exists():
        data = json.loads(CACHE.read_text())
        if data.get("count") == n:
            _COMPANIES = data["companies"]
            return _COMPANIES
    _COMPANIES = sorted({m["company"] for m in all_metadatas() if "company" in m})
    CACHE.write_text(json.dumps({"count": n, "companies": _COMPANIES}))
    return _COMPANIES


def resolve_company(name):
    """Dopasuj wpisaną nazwę do dokładnej wartości z bazy (albo None)."""
    companies = load_companies()
    key = norm_company(name)
    if key in companies:
        return key
    sub = [c for c in companies if key in c or c in key]
    if sub:
        return min(sub, key=len)
    close = difflib.get_close_matches(key, companies, n=1, cutoff=0.6)
    return close[0] if close else None


# ---------- filtry ----------

def build_where(company=None, year=None, quarter=None, year_from=None, year_to=None):
    conds = []
    if company:
        conds.append({"company": company})
    if year is not None:
        conds.append({"year": int(year)})
    if year_from is not None:
        conds.append({"year": {"$gte": int(year_from)}})
    if year_to is not None:
        conds.append({"year": {"$lte": int(year_to)}})
    if quarter is not None:
        conds.append({"quarter": int(quarter)})
    if not conds:
        return None
    return conds[0] if len(conds) == 1 else {"$and": conds}


_ORDINALS = {"first": 1, "second": 2, "third": 3, "fourth": 4}

def detect_filters(question):
    """Wyciąga spółkę, rok i kwartał z pytania (best effort)."""
    q = question.lower()
    company = None
    for c in load_companies():
        if len(c) >= 3 and re.search(rf"\b{re.escape(c.replace('-', ' '))}\b", q):
            company = c
            break
    year = re.search(r"\b(20\d{2}|19\d{2})\b", q)
    quarter = re.search(r"\bq([1-4])\b", q)
    qn = int(quarter.group(1)) if quarter else None
    if qn is None:
        m = re.search(r"\b(first|second|third|fourth) quarter\b", q)
        qn = _ORDINALS[m.group(1)] if m else None
    return {"company": company, "year": int(year.group(1)) if year else None, "quarter": qn}


# ---------- retrieval ----------

def retrieve(query, k=5, where=None):
    q = model.encode([QUERY_PREFIX + query], normalize_embeddings=True).tolist()
    res = collection.query(query_embeddings=q, n_results=k, where=where)
    return list(zip(res["documents"][0], res["metadatas"][0], res["distances"][0]))


def search(query, k=5, company=None, year=None, quarter=None, auto=False):
    """Wygodna funkcja: company może być dowolną nazwą (resolver), auto=True wykrywa filtry z pytania."""
    if auto:
        found = detect_filters(query)
        company = company or found["company"]
        year = year if year is not None else found["year"]
        quarter = quarter if quarter is not None else found["quarter"]
    if company:
        resolved = resolve_company(company)
        if resolved is None:
            print(f"[uwaga] nie znaleziono spółki '{company}', szukam bez filtra spółki")
        company = resolved
    where = build_where(company, year, quarter)
    return retrieve(query, k, where), where


# ---------- CLI ----------

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=5)
    ap.add_argument("--company")
    ap.add_argument("--year", type=int)
    ap.add_argument("--quarter", type=int)
    ap.add_argument("--auto", action="store_true", help="wykryj filtry z treści pytania")
    args = ap.parse_args()

    hits, where = search(args.query, args.k, args.company, args.year, args.quarter, args.auto)
    print("filtr:", where, "| trafień:", len(hits), "\n")
    for doc, meta, dist in hits:
        print(f"{meta['source']}  (dist={dist:.3f})")
        print(doc[:300].replace("\n", " "), "\n")