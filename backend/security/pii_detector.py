from functools import lru_cache

import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification

from config import PII_MODEL

MAX_LENGTH = 512
STRIDE     = 64


@lru_cache(maxsize=1)
def _load():
    tokenizer = AutoTokenizer.from_pretrained(PII_MODEL)
    model = AutoModelForTokenClassification.from_pretrained(PII_MODEL, device_map="auto")
    return tokenizer, model


def detect_pii(text: str) -> list[dict]:
    """Zwraca wykryte encje PII: [{"type", "text", "start", "end"}], w kolejności wystąpienia.

    Tekst dłuższy niż okno modelu jest skanowany w nakładających się fragmentach.
    """
    if not text.strip():
        return []

    tokenizer, model = _load()
    enc = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=MAX_LENGTH,
        stride=STRIDE,
        return_overflowing_tokens=True,
        return_offsets_mapping=True,
        padding=True,
    )
    offsets = enc.pop("offset_mapping")
    enc.pop("overflow_to_sample_mapping", None)

    with torch.no_grad():
        logits = model(**enc.to(model.device)).logits
    predictions = torch.argmax(logits, dim=-1).cpu()

    # Etykieta na każdy znak — fragmenty się nakładają, więc scalamy po pozycjach w tekście.
    char_labels = [None] * len(text)
    for chunk_preds, chunk_offsets in zip(predictions, offsets):
        for pred, (start, end) in zip(chunk_preds, chunk_offsets.tolist()):
            label = model.config.id2label[pred.item()]
            if label == "O" or start == end:
                continue
            entity_type = label.split("-", 1)[-1]
            for i in range(start, end):
                char_labels[i] = entity_type

    entities = []
    i = 0
    while i < len(text):
        entity_type = char_labels[i]
        if entity_type is None:
            i += 1
            continue
        start = i
        while i < len(text) and char_labels[i] == entity_type:
            i += 1
        prev = entities[-1] if entities else None
        if prev and prev["type"] == entity_type and not text[prev["end"]:start].strip():
            prev["end"] = i
        else:
            entities.append({"type": entity_type, "start": start, "end": i})

    # Offsety tokenizera obejmują spację przed słowem — przycinamy ją.
    for e in entities:
        raw = text[e["start"]:e["end"]]
        e["start"] += len(raw) - len(raw.lstrip())
        e["text"] = raw.strip()
        e["end"] = e["start"] + len(e["text"])
    return entities
