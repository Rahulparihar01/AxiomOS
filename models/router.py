from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from config.settings import settings
from kernel.process import ProcessControlBlock, PriorityLevel
from models.provider import BaseModelProvider, MockProvider, GeminiProvider, OpenAIProvider, ModelResponse, get_provider

class ModelTier(str, Enum):
    REASONING = "REASONING"    # Complex planning, architecture, synthesis
    FAST = "FAST"              # High-throughput, low latency, sub-workers
    FALLBACK = "FALLBACK"      # Offline or rate-limit degraded fallback

class AdaptiveModelRouter:
    """
    Adaptive Multi-Model Compute Router with Circuit Breaker Failover.
    Routes agent execution steps to the optimal LLM compute tier based on task
    priority, agent role complexity, and provider health.
    """
    def __init__(
        self,
        reasoning_provider: Optional[BaseModelProvider] = None,
        fast_provider: Optional[BaseModelProvider] = None,
        fallback_provider: Optional[BaseModelProvider] = None,
        failure_threshold: int = 3
    ):
        base_provider = settings.default_provider
        
        # Default providers based on current system settings
        self.reasoning_provider = reasoning_provider or get_provider(base_provider, settings, model_name=settings.reasoning_model)
        self.fast_provider = fast_provider or get_provider(base_provider, settings, model_name=settings.fast_model)
        self.fallback_provider = fallback_provider or MockProvider()
        self.failure_threshold = failure_threshold
        self.consecutive_failures = 0
        self.circuit_open = False
        self.fallback_invocations = 0

    def get_tier_for_process(self, pcb: ProcessControlBlock) -> ModelTier:
        """Determine appropriate compute tier for a given process."""
        name_lower = pcb.name.lower()
        if (
            pcb.priority in (PriorityLevel.CRITICAL, PriorityLevel.HIGH)
            or "planner" in name_lower
            or "architect" in name_lower
            or "lead" in name_lower
        ):
            return ModelTier.REASONING
        return ModelTier.FAST

    def route(self, pcb: ProcessControlBlock) -> BaseModelProvider:
        """Return the optimal model provider instance for the calling process."""
        tier = self.get_tier_for_process(pcb)
        if tier == ModelTier.REASONING:
            return self.reasoning_provider
        return self.fast_provider

    async def generate_with_fallback(
        self,
        pcb: ProcessControlBlock,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Callable[[str], Any]] = None
    ) -> ModelResponse:
        """
        Execute model inference with automatic circuit breaker failover.
        If the routed provider experiences rate limits (429), server errors (5xx),
        or connectivity exceptions, fail over seamlessly to fallback_provider.
        """
        primary = self.route(pcb)

        if not self.circuit_open:
            try:
                if on_token is not None:
                    try:
                        resp = await primary.generate(
                            system_prompt=system_prompt,
                            messages=messages,
                            tools=tools,
                            on_token=on_token
                        )
                    except TypeError:
                        resp = await primary.generate(
                            system_prompt=system_prompt,
                            messages=messages,
                            tools=tools
                        )
                else:
                    resp = await primary.generate(
                        system_prompt=system_prompt,
                        messages=messages,
                        tools=tools
                    )
                self.consecutive_failures = 0
                return resp
            except Exception:
                self.consecutive_failures += 1
                if self.consecutive_failures >= self.failure_threshold:
                    self.circuit_open = True

        self.fallback_invocations += 1
        if on_token is not None:
            try:
                return await self.fallback_provider.generate(
                    system_prompt=system_prompt,
                    messages=messages,
                    tools=tools,
                    on_token=on_token
                )
            except TypeError:
                return await self.fallback_provider.generate(
                    system_prompt=system_prompt,
                    messages=messages,
                    tools=tools
                )
        else:
            return await self.fallback_provider.generate(
                system_prompt=system_prompt,
                messages=messages,
                tools=tools
            )

    async def aclose(self) -> None:
        """Close connection pools of all registered tier providers."""
        for p in (self.reasoning_provider, self.fast_provider, self.fallback_provider):
            if hasattr(p, "aclose"):
                try:
                    await p.aclose()
                except Exception:
                    pass
