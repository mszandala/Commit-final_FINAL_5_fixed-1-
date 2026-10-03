"""Pomiar wykrywania odmów chatbota na tests/datasets/refusal_samples.json.

Porównuje trzy mechanizmy:
  - słowa kluczowe (wyrażenia regularne, PL + EN),
  - embeddingi z ręcznie napisanymi wzorcami odmów,
  - embeddingi ze wzorcami wziętymi z prawdziwych odmów (walidacja krzyżowa: wzorce z jednej
    części próbek, pomiar na pozostałych).

Użycie (z katalogu backend/):  python eval_refusals.py [-v]
"""
import argparse
import json
import re
import time
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from transformers import PreTrainedTokenizerFast

DATASET = Path(__file__).parent / "tests" / "datasets" / "refusal_samples.json"
MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]

KEYWORDS = re.compile(
    r"i(?:'m| am) sorry|i cannot|i can't|i am unable|i'm unable|not authorized|do(?:es)? not have (?:the )?(?:authorization|permission|ability|access)"
    r"|don't have (?:the )?(?:authorization|permission|ability|access|necessary)|only authorized"
    r"|przykro mi|przepraszam, ale|nie mam uprawnień|nie mam dostępu|nie mam możliwości|nie mogę",
    re.IGNORECASE,
)

# Ogólne wzorce odmów, pisane bez zaglądania do próbek; pogrupowane według przyczyny.
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

def load_model() -> SentenceTransformer:
    """Model embeddingów z tokenizerem wczytanym wprost z jego pliku tokenizer.json.

    Automatyczny wybór tokenizera w zainstalowanej wersji transformers bierze dla tego modelu
    klasę BertTokenizer, która większość słów zamienia na <unk> — embeddingi są wtedy bezużyteczne.
    """
    model = SentenceTransformer(MODEL)
    tokenizer_file = Path(model[0].auto_model.config._name_or_path)
    if not (tokenizer_file / "tokenizer.json").exists():
        from huggingface_hub import snapshot_download
        tokenizer_file = Path(snapshot_download(MODEL, allow_patterns=["tokenizer.json"]))
    model.tokenizer = PreTrainedTokenizerFast(
        tokenizer_file=str(tokenizer_file / "tokenizer.json"), bos_token="<s>", eos_token="</s>", unk_token="<unk>",
        sep_token="</s>", pad_token="<pad>", cls_token="<s>", mask_token="<mask>")
    return model


_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE.split(text) if len(s.strip()) > 3]


def embed(model, texts: list[str]) -> np.ndarray:
    return model.encode(texts, normalize_embeddings=True, show_progress_bar=False)


def scores(model, replies: list[str], exemplar_vectors: np.ndarray) -> list[float]:
    """Dla każdej odpowiedzi: największe podobieństwo któregokolwiek zdania do któregokolwiek wzorca."""
    out = []
    for reply in replies:
        parts = sentences(reply) or [reply]
        out.append(float((embed(model, parts) @ exemplar_vectors.T).max()))
    return out


def report(name: str, predicted: list[bool], truth: list[bool]) -> tuple[int, int]:
    tp = sum(p and t for p, t in zip(predicted, truth))
    fp = sum(p and not t for p, t in zip(predicted, truth))
    fn = sum(t and not p for p, t in zip(predicted, truth))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"  {name:22} wykryte odmowy {tp:2}/{tp + fn:2} ({recall:4.0%}) | fałszywe alarmy {fp:2}/{len(truth) - tp - fn:2}"
          f" | precyzja {precision:4.0%}")
    return fp, fn


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="pokaż pomyłki przy najlepszym progu")
    args = parser.parse_args()

    samples = json.loads(DATASET.read_text(encoding="utf-8"))
    replies = [s["reply"] for s in samples]
    truth = [s["refusal"] for s in samples]
    print(f"Próbki: {len(samples)} (odmowy: {sum(truth)}, zwykłe odpowiedzi: {len(truth) - sum(truth)})\n")

    print("Słowa kluczowe")
    started = time.perf_counter()
    by_keywords = [bool(KEYWORDS.search(r)) for r in replies]
    keyword_ms = (time.perf_counter() - started) * 1000 / len(replies)
    report("wyrażenia regularne", by_keywords, truth)

    started = time.perf_counter()
    model = load_model()
    load_s = time.perf_counter() - started
    exemplar_vectors = embed(model, [e for group in EXEMPLARS.values() for e in group])
    embed(model, ["rozgrzewka"])
    started = time.perf_counter()
    handwritten = scores(model, replies, exemplar_vectors)
    embedding_ms = (time.perf_counter() - started) * 1000 / len(replies)

    print("\nEmbeddingi, wzorce napisane ręcznie")
    results = {}
    for threshold in THRESHOLDS:
        results[threshold] = report(f"próg {threshold:.2f}", [s >= threshold for s in handwritten], truth)

    # Wzorce z prawdziwych odmów: 5 części, wzorce z czterech, pomiar na piątej (każda próbka oceniana raz).
    print("\nEmbeddingi, wzorce z prawdziwych odmów (walidacja krzyżowa, 5 części)")
    folds = 5
    cross = [0.0] * len(samples)
    for fold in range(folds):
        test = [i for i in range(len(samples)) if i % folds == fold]
        train = [sentences(replies[i])[0] for i in range(len(samples)) if i % folds != fold and truth[i]]
        vectors = embed(model, train)
        for i, score in zip(test, scores(model, [replies[i] for i in test], vectors)):
            cross[i] = score
    for threshold in THRESHOLDS:
        report(f"próg {threshold:.2f}", [s >= threshold for s in cross], truth)

    print(f"\nCzas na odpowiedź: słowa kluczowe {keyword_ms:.3f} ms, embeddingi {embedding_ms:.0f} ms"
          f" (wczytanie modelu jednorazowo {load_s:.1f} s)")

    if args.verbose:
        best = min(THRESHOLDS, key=lambda t: sum(results[t]))
        print(f"\nPomyłki przy wzorcach ręcznych i progu {best:.2f}:")
        for sample, score in zip(samples, handwritten):
            if (score >= best) != sample["refusal"]:
                kind = "pominięta odmowa" if sample["refusal"] else "fałszywy alarm"
                print(f"  [{kind}, {score:.2f}] {sample['reply'][:140]!r}")
        print("\nPomyłki słów kluczowych:")
        for sample, hit in zip(samples, by_keywords):
            if hit != sample["refusal"]:
                kind = "pominięta odmowa" if sample["refusal"] else "fałszywy alarm"
                print(f"  [{kind}] {sample['reply'][:140]!r}")


if __name__ == "__main__":
    main()
