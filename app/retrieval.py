"""Hybrid retrieval: BM25 + hashed-n-gram vectors fused with reciprocal rank fusion.

The hashing embedder is dependency-free and deterministic, which makes the lab
reproducible. It is NOT semantic. Swap in a real embedding model behind the same
`embed`/`pack`/`unpack` interface for production-like behaviour.
"""
from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from array import array
from dataclasses import dataclass

from app.db import Database

STOPWORDS = frozenset(
    "a an and are as at be by for from has have how i in is it its of on or our that the their this to was were what when where which who why will with you your do does did can could should would my me we us".split()
)
_TOKEN = re.compile(r"\w{2,}", re.UNICODE)
MIN_COSINE = 0.30


def _stem(token: str) -> str:
    """Very light plural stripping so 'passwords' matches 'password' (not a real stemmer)."""
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def tokenize(text: str) -> list[str]:
    text = unicodedata.normalize("NFKC", text).lower()
    return [_stem(t) for t in _TOKEN.findall(text) if t not in STOPWORDS]


class HashingEmbedder:
    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for tok in tokenize(text):
            feats = [tok] + [f"#{tok[i:i + 3]}" for i in range(max(len(tok) - 2, 1))]
            for feat in feats:
                h = int.from_bytes(hashlib.blake2b(feat.encode(), digest_size=8).digest(), "big")
                vec[h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm else vec

    @staticmethod
    def pack(vec: list[float]) -> bytes:
        return array("f", vec).tobytes()

    @staticmethod
    def unpack(blob: bytes) -> list[float]:
        a = array("f")
        a.frombytes(blob)
        return list(a)


@dataclass(frozen=True)
class Hit:
    chunk_id: str
    document_id: str
    tenant_id: str
    title: str
    text: str
    score: float


def _bm25(query_terms: list[str], docs: list[list[str]], k1: float = 1.5, b: float = 0.75) -> list[float]:
    n = len(docs)
    if n == 0:
        return []
    avg = sum(len(d) for d in docs) / n or 1.0
    df: dict[str, int] = {}
    for d in docs:
        for t in set(d):
            df[t] = df.get(t, 0) + 1
    scores = []
    for d in docs:
        tf: dict[str, int] = {}
        for t in d:
            tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for t in set(query_terms):
            if t not in tf:
                continue
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * len(d) / avg))
        scores.append(s)
    return scores


def search(db: Database, query: str, tenant_id: str | None, *, scoped: bool, top_k: int = 4,
           embedder: HashingEmbedder | None = None) -> list[Hit]:
    """`scoped=True` restricts to one tenant at the SQL layer and requires a tenant id.
    `scoped=False` is the deliberately vulnerable lab path (all tenants)."""
    chunks = db.iter_chunks(tenant_id) if scoped else db.iter_chunks_all_tenants_unsafe()  # type: ignore[arg-type]
    terms = tokenize(query)
    if not chunks or not terms:
        return []
    embedder = embedder or HashingEmbedder()
    bm = _bm25(terms, [tokenize(c["text"]) for c in chunks])
    qvec = embedder.embed(query)
    cos = []
    for c in chunks:
        blob = c.get("embedding")
        v = embedder.unpack(blob) if blob else embedder.embed(c["text"])
        cos.append(sum(x * y for x, y in zip(qvec, v)))
    lex_rank = {i: r for r, i in enumerate(sorted((i for i, s in enumerate(bm) if s > 0), key=lambda i: -bm[i]))}
    vec_rank = {i: r for r, i in enumerate(sorted((i for i, s in enumerate(cos) if s >= MIN_COSINE), key=lambda i: -cos[i]))}
    fused: dict[int, float] = {}
    for rank_map in (lex_rank, vec_rank):
        for i, r in rank_map.items():
            fused[i] = fused.get(i, 0.0) + 1.0 / (60 + r)
    order = sorted(fused, key=lambda i: (-fused[i], i))[:top_k]
    return [Hit(chunks[i]["chunk_id"], chunks[i]["document_id"], chunks[i]["tenant_id"], chunks[i]["title"],
                chunks[i]["text"], round(fused[i], 5)) for i in order]
