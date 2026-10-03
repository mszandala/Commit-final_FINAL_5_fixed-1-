"""Wykrywanie odmowy w odpowiedzi chatbota.

Chatbot nie zgłasza, że odmówił — rozpoznajemy to po treści, dwoma lokalnymi sygnałami:
  1. słowa kluczowe (wyrażenia regularne, PL + EN),
  2. podobieństwo zdań odpowiedzi do wzorcowych odmów (embeddingi), gdy słowa kluczowe nic nie znalazły.
Pomiar obu sygnałów: eval_refusals.py.
"""
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from chatbot import llm_client
from config import REFUSAL_EMBEDDINGS_ENABLED, REFUSAL_MODEL, REFUSAL_THRESHOLD, REFUSAL_TRIGGER_THRESHOLD

_JUDGE_PROMPT = (Path(__file__).parent / "prompts" / "refusal_judge.txt").read_text(encoding="utf-8")
MAX_JUDGED_CHARS = 4000   # tyle znaków promptu i odpowiedzi widzi sędzia odmów

KEYWORDS = re.compile(
    r"i(?:'m| am) sorry|i cannot|i can't|i am unable|i'm unable|not authorized|do(?:es)? not have (?:the )?(?:authorization|permission|ability|access)"
    r"|don't have (?:the )?(?:authorization|permission|ability|access|necessary)|only authorized"
    r"|przykro mi|przepraszam, ale|nie mam uprawnień|nie mam dostępu|nie mam możliwości|nie mogę",
    re.IGNORECASE,
)

# Ogólne wzorce odmów pogrupowane według przyczyny; z grupy najbliższego wzorca bierzemy kategorię.
EXEMPLARS = {
    "no_permission": [
        "I'm sorry, but I am not authorized to access that data.",
        "I don't have permission to view this information for your role.",
        "My access is limited to other data, so I can't retrieve this.",
        "Przykro mi, ale nie mam uprawnień do tych danych.",
        "Twoja rola nie ma dostępu do tych informacji.",
        "Nie mam dostępu do tych danych.",
    ],
    "no_capability": [
        "I don't have the ability to do that.",
        "I can't perform this action; I can only answer questions using my tools.",
        "Nie mam możliwości wykonania tej czynności.",
        "Nie potrafię tego zrobić, mogę jedynie odpowiadać na pytania.",
    ],
    "conduct_rule": [
        "I cannot make that decision; it must be made by an authorized person.",
        "I can't help with this request because it would violate the rules I must follow.",
        "Nie mogę podjąć takiej decyzji, musi ją podjąć upoważniona osoba.",
        "Nie mogę spełnić tej prośby, bo naruszałaby obowiązujące zasady.",
    ],
    "generic": [
        "I cannot fulfill this request.",
        "I'm unable to help with that.",
        "Nie mogę spełnić tej prośby.",
        "Niestety nie mogę w tym pomóc.",
    ],
}
# Nazwy kategorii: po angielsku dla opisów kroków w interfejsie, po polsku dla powodu decyzji.
CATEGORIES = {
    "no_permission": "no permission for the role",
    "no_capability": "outside the chatbot's capabilities",
    "conduct_rule": "conduct rule",
    "generic": "unspecified",
}
CATEGORIES_PL = {
    "no_permission": "brak uprawnień roli",
    "no_capability": "poza możliwościami chatbota",
    "conduct_rule": "reguła postępowania",
    "generic": "bez podanej przyczyny",
}

_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
_log = logging.getLogger(__name__)


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE.split(text) if len(s.strip()) > 3]


def load_model():
    """Model embeddingów z tokenizerem wczytanym wprost z jego pliku tokenizer.json.

    Automatyczny wybór tokenizera w części wersji transformers bierze dla tego modelu klasę
    BertTokenizer, która większość słów zamienia na <unk> — embeddingi są wtedy bezużyteczne.
    """
    from huggingface_hub import snapshot_download
    from sentence_transformers import SentenceTransformer
    from transformers import PreTrainedTokenizerFast

    model = SentenceTransformer(REFUSAL_MODEL)
    try:
        folder = Path(snapshot_download(REFUSAL_MODEL, allow_patterns=["tokenizer.json"], local_files_only=True))
    except Exception:
        folder = Path(snapshot_download(REFUSAL_MODEL, allow_patterns=["tokenizer.json"]))
    tokenizer = PreTrainedTokenizerFast(
        tokenizer_file=str(folder / "tokenizer.json"), bos_token="<s>", eos_token="</s>", unk_token="<unk>",
        sep_token="</s>", pad_token="<pad>", cls_token="<s>", mask_token="<mask>")
    try:
        model.tokenizer = tokenizer
    except AttributeError:      # sentence-transformers 6: tokenizer jest tylko do odczytu, bierze się z processor
        model[0].processor = tokenizer
    return model


@lru_cache(maxsize=1)
def _embedder():
    """(model, wektory wzorców, kategorie wzorców) albo None, gdy modelu nie da się wczytać."""
    try:
        model = load_model()
        labels = [category for category, group in EXEMPLARS.items() for _ in group]
        vectors = model.encode([e for group in EXEMPLARS.values() for e in group],
                               normalize_embeddings=True, show_progress_bar=False)
        return model, vectors, labels
    except Exception as exc:
        _log.warning("Model wykrywania odmów niedostępny, zostają same słowa kluczowe: %s", exc)
        return None


def warm_up() -> None:
    if REFUSAL_EMBEDDINGS_ENABLED:
        _embedder()


def _nearest(text: str) -> Optional[tuple[float, str]]:
    """Największe podobieństwo któregokolwiek zdania do wzorca odmowy i kategoria tego wzorca."""
    embedder = _embedder() if REFUSAL_EMBEDDINGS_ENABLED else None
    parts = sentences(text) or [text]
    if embedder is None or not text.strip():
        return None
    model, vectors, labels = embedder
    similarity = model.encode(parts, normalize_embeddings=True, show_progress_bar=False) @ vectors.T
    best = similarity.max(axis=0).argmax()
    return float(similarity.max()), labels[best]


def detect_refusal(reply: str) -> Optional[dict]:
    """Zwraca {"method", "category", "score"} gdy odpowiedź jest odmową (w całości lub części), inaczej None.

    `method`: "keywords" albo "embedding"; `score`: podobieństwo do najbliższego wzorca (None bez modelu).
    """
    if not reply or not reply.strip():
        return None
    by_keywords = bool(KEYWORDS.search(reply))
    nearest = _nearest(reply)
    score, category = nearest if nearest else (None, "generic")
    if by_keywords:
        return {"method": "keywords", "category": category, "score": round(score, 2) if score is not None else None}
    if score is not None and score >= REFUSAL_THRESHOLD:
        return {"method": "embedding", "category": category, "score": round(score, 2)}
    return None


def verify_refusal(prompt: str, reply: str) -> Optional[dict]:
    """Sędzia LLM (strefa bezpieczeństwa): {"refusal", "category", "reason"} albo None, gdy nie odpowiedział
    czytelnie."""
    message = _JUDGE_PROMPT.format(prompt=prompt[:MAX_JUDGED_CHARS], reply=reply[:MAX_JUDGED_CHARS])
    try:
        answer = llm_client.chat([{"role": "user", "content": message}], zone="security", purpose="refusal_judge")
        match = re.search(r"\{.*\}", answer.content or "", re.DOTALL)
        parsed = json.loads(match.group(0)) if match else {}
    except Exception:
        return None
    if not isinstance(parsed.get("refusal"), bool):
        return None
    category = parsed.get("category")
    return {"refusal": parsed["refusal"], "category": category if category in CATEGORIES else "generic",
            "reason": str(parsed.get("reason", "")).strip()[:200]}


def assess_refusal(prompt: str, reply: str, denied_tools: bool = False, judge: bool = True) -> Optional[dict]:
    """Ocena odmowy: słowa kluczowe i podobieństwo do wzorców tylko wskazują kandydata, rozstrzyga sędzia LLM.

    Kandydatem jest odpowiedź ze słowem kluczowym, podobna do wzorca odmowy (niższy próg
    REFUSAL_TRIGGER_THRESHOLD) albo udzielona po odrzuceniu narzędzia. Zwraca
    {"refusal", "method", "category", "score", "reason"}; None, gdy odpowiedź nie jest kandydatem.
    Gdy sędzia jest wyłączony albo nie odpowie, zostaje sama heurystyka (jak detect_refusal).
    """
    if not reply or not reply.strip():
        return None
    by_keywords = bool(KEYWORDS.search(reply))
    nearest = _nearest(reply)
    score, category = nearest if nearest else (None, "generic")
    rounded = round(score, 2) if score is not None else None
    candidate = by_keywords or denied_tools or (score is not None and score >= REFUSAL_TRIGGER_THRESHOLD)
    if not candidate:
        return None
    judged = verify_refusal(prompt, reply) if judge else None
    if judged:
        return {"refusal": judged["refusal"], "method": "llm", "score": rounded, "reason": judged["reason"],
                "category": judged["category"] if judged["refusal"] else category}
    heuristic = detect_refusal(reply)
    return {"refusal": True, "reason": "", **heuristic} if heuristic else None
