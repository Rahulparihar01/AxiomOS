from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from memory.l3_semantic import BaseTextVectorizer, TextVectorizer, get_vectorizer
from memory.l4_archival import L4ArchivalStore

class CostEstimate(BaseModel):
    """Statistical prediction of token consumption for admission control."""
    predicted_tokens_p50: int = Field(description="Median (50th percentile) predicted token cost.")
    predicted_tokens_p90: int = Field(description="90th percentile predicted token cost for safety margins.")
    confidence: float = Field(default=0.0, description="Confidence score from 0.0 (cold start) to 1.0.")
    sample_size: int = Field(default=0, description="Number of historical sample tasks used.")

class CostEstimator:
    """
    Predictive Task Cost Estimator for the AI-OS Scheduler.
    Performs proactive admission control before token spend by comparing
    incoming task embeddings against completed task history in L4.
    """
    def __init__(
        self,
        l4_store: Optional[L4ArchivalStore] = None,
        dimensions: int = 128,
        vectorizer: Optional[BaseTextVectorizer] = None
    ):
        self.l4_store = l4_store or L4ArchivalStore()
        self.vectorizer = vectorizer or get_vectorizer(dimensions=dimensions)

    def estimate(self, role: str, instruction: str) -> CostEstimate:
        """
        Estimate the token consumption for a given agent role and task instruction.
        Returns a CostEstimate with p50, p90, confidence, and sample size.
        """
        records = self.l4_store.get_task_cost_history(role=role, limit=100)

        # Fallback if no matching role history: look across all roles
        if not records:
            records = self.l4_store.get_task_cost_history(role=None, limit=50)

        if not records:
            # Cold-start defaults
            return CostEstimate(
                predicted_tokens_p50=2500,
                predicted_tokens_p90=6000,
                confidence=0.0,
                sample_size=0
            )

        query_vec = self.vectorizer.vectorize(instruction)

        # Score historical records by instruction similarity
        scored_samples: List[tuple[float, int]] = [] # (similarity, tokens_consumed)
        for rec in records:
            hist_instr = rec.get("instruction", "")
            hist_tokens = rec.get("tokens_consumed", 0)
            hist_vec = self.vectorizer.vectorize(hist_instr)
            sim = max(0.0, self.vectorizer.cosine_similarity(query_vec, hist_vec))
            scored_samples.append((sim, hist_tokens))

        # Valid samples with positive token counts
        valid_samples = [(sim, tokens) for sim, tokens in scored_samples if tokens > 0]
        if not valid_samples:
            return CostEstimate(
                predicted_tokens_p50=2500,
                predicted_tokens_p90=6000,
                confidence=0.0,
                sample_size=len(records)
            )

        best_similarity = max(sim for sim, _ in valid_samples)

        # Similarity-weighted percentiles (Remediates GAP-08):
        # 1. If strong semantic matches exist, isolate the relevant task cluster
        #    so completely unrelated task types (e.g. kernel compilation vs simple math)
        #    cannot distort the percentiles or cause unwarranted priority downgrades.
        if best_similarity >= 0.5:
            threshold = max(0.4, best_similarity * 0.6)
            cluster_samples = [s for s in valid_samples if s[0] >= threshold]
        elif best_similarity >= 0.3:
            threshold = max(0.25, best_similarity * 0.5)
            cluster_samples = [s for s in valid_samples if s[0] >= threshold]
        else:
            cluster_samples = valid_samples

        if not cluster_samples:
            cluster_samples = valid_samples

        # 2. Sort by token consumption ascending and apply non-linear similarity weights
        sorted_pairs = sorted(cluster_samples, key=lambda x: x[1])
        weighted_samples = [(tokens, max(0.001, (sim + 0.05) ** 2)) for sim, tokens in sorted_pairs]
        total_weight = sum(w for _, w in weighted_samples)

        def _calc_percentile(target_pct: float) -> int:
            cumulative = 0.0
            for tokens, w in weighted_samples:
                cumulative += w
                if (cumulative / total_weight) >= target_pct:
                    return tokens
            return weighted_samples[-1][0]

        p50 = _calc_percentile(0.50)
        p90 = _calc_percentile(0.90)

        # Calculate confidence: combination of sample size and similarity to nearest historical task
        sample_factor = min(1.0, len(valid_samples) / 10.0)
        confidence = round(min(0.95, 0.2 * sample_factor + 0.8 * best_similarity), 2)

        return CostEstimate(
            predicted_tokens_p50=p50,
            predicted_tokens_p90=p90,
            confidence=confidence,
            sample_size=len(valid_samples)
        )
