import re
from pathlib import Path
import chromadb
import time
from tqdm import tqdm  
from sentence_transformers import SentenceTransformer

DOCS_DIR = Path("backend/data/stock_market/cleaned_ECTs_dataset")
DB_DIR = "backend/data/vector_db"
MAX_CHARS, OVERLAP_PARAS = 1200, 1
BATCH = 64
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

model = SentenceTransformer("BAAI/bge-small-en-v1.5")
model.max_seq_length = 384

client = chromadb.PersistentClient(path=DB_DIR)
collection = client.get_or_create_collection(
    "earnings_calls", metadata={"hnsw:space": "cosine"}
)


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


def norm_company(name):
    return re.sub(r"[\s_]+", "-", name.strip().lower())


def parse_meta(path):
    meta = {"company": norm_company(path.parent.name)}
    parts = path.stem.split("_")
    if len(parts) >= 2 and parts[0].isdigit():
        q = re.sub(r"\D", "", parts[1])
        meta["year"] = int(parts[0])
        meta["quarter"] = int(q) if q else 0
        meta["period"] = f"{parts[0]}-Q{q}" if q else parts[0]
    return meta


def new_buffer():
    return {"ids": [], "docs": [], "to_embed": [], "metas": []}


def flush(buf):
    if not buf["ids"]:
        return
    embeddings = model.encode(
        buf["to_embed"],
        normalize_embeddings=True,
        batch_size=32,
        show_progress_bar=False,
    ).tolist()
    collection.upsert(
        ids=buf["ids"],
        documents=buf["docs"],
        embeddings=embeddings,
        metadatas=buf["metas"],
    )
    for lst in buf.values():
        lst.clear()


def build_index():
    buf = new_buffer()
    files = sorted(DOCS_DIR.glob("*/*.txt"))
    print(f"Znaleziono plików: {len(files)}", flush=True)
    t0 = time.time()
    for path in tqdm(files, desc="pliki"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(DOCS_DIR).as_posix()
        base = {"source": rel, **parse_meta(path)}
        for i, chunk in enumerate(chunk_paragraphs(text)):
            buf["ids"].append(f"{rel}-{i}")
            buf["docs"].append(chunk)
            buf["to_embed"].append(f"{base['company']} {base.get('period', '')}\n{chunk}")
            buf["metas"].append({**base, "chunk": i})
            if len(buf["ids"]) >= BATCH:
                flush(buf)
    flush(buf)
    print(f"Gotowe: {collection.count()} chunków w {round(time.time() - t0)} s")


def retrieve(query, k=5, where=None):
    q = model.encode([QUERY_PREFIX + query], normalize_embeddings=True).tolist()
    res = collection.query(query_embeddings=q, n_results=k, where=where)
    return list(zip(res["documents"][0], res["metadatas"][0], res["distances"][0]))


if __name__ == "__main__":
    build_index()