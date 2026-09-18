import asyncio
import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from config.settings import settings
from models.provider import GeminiProvider, OpenAIProvider, MockProvider
from models.router import AdaptiveModelRouter
from memory.l3_semantic import (
    BaseTextVectorizer,
    HashTextVectorizer,
    DenseEmbeddingVectorizer,
    TextVectorizer,
    get_vectorizer,
    L3SemanticStore
)
from kernel.cost_estimator import CostEstimator
from sandbox.runner import (
    BaseCodeRunner,
    IsolatedCodeRunner,
    DockerIsolatedRunner,
    DockerCodeRunner,
    get_code_runner,
    ExecutionResult
)
from syscalls.sandbox import SysExecPython
from kernel.process import ProcessControlBlock, ProcessState

class TestScalabilityEnhancements(unittest.IsolatedAsyncioTestCase):
    """
    Test suite verifying scalability enhancements:
    1. HTTP connection pooling and client lifecycle management.
    2. Pluggable vectorizer architecture and dense embedding fallback.
    3. Pluggable sandbox execution backends (Docker & Local).
    """

    # -------------------------------------------------------------
    # 1. HTTP Connection Pooling Tests
    # -------------------------------------------------------------
    async def test_openai_provider_connection_pooling_and_reuse(self):
        """Verify OpenAIProvider initializes pooled client and reuses it across calls."""
        provider = OpenAIProvider(api_key="sk-test-key", model="gpt-4o-mini")
        
        # 1. Lazy initialization
        self.assertIsNone(provider._client)
        client1 = await provider.get_client()
        self.assertIsInstance(client1, httpx.AsyncClient)
        self.assertFalse(client1.is_closed)

        # 2. Connection reuse across subsequent calls
        client2 = await provider.get_client()
        self.assertIs(client1, client2)

        # 3. Clean teardown with aclose
        await provider.aclose()
        self.assertTrue(client1.is_closed)
        self.assertIsNone(provider._client)

    async def test_gemini_provider_connection_pooling_and_reuse(self):
        """Verify GeminiProvider initializes pooled client and reuses it across calls."""
        provider = GeminiProvider(api_key="gemini-test-key", model="gemini-1.5-flash")
        
        client1 = await provider.get_client()
        self.assertIsInstance(client1, httpx.AsyncClient)
        self.assertFalse(client1.is_closed)

        client2 = await provider.get_client()
        self.assertIs(client1, client2)

        await provider.aclose()
        self.assertTrue(client1.is_closed)
        self.assertIsNone(provider._client)

    async def test_router_aclose_lifecycle(self):
        """Verify AdaptiveModelRouter cleanly closes all tier provider pools."""
        p_reasoning = OpenAIProvider(api_key="test-key", model="gpt-4o")
        p_fast = GeminiProvider(api_key="test-key", model="gemini-1.5-flash")
        p_fallback = MockProvider()

        # Initialize clients
        c_reasoning = await p_reasoning.get_client()
        c_fast = await p_fast.get_client()

        router = AdaptiveModelRouter(
            reasoning_provider=p_reasoning,
            fast_provider=p_fast,
            fallback_provider=p_fallback
        )

        await router.aclose()
        self.assertTrue(c_reasoning.is_closed)
        self.assertTrue(c_fast.is_closed)

    # -------------------------------------------------------------
    # 2. Pluggable Vectorizer & Embedding Tests
    # -------------------------------------------------------------
    def test_hash_vectorizer_deterministic_output(self):
        """Verify HashTextVectorizer produces normalized deterministic vectors."""
        vec = HashTextVectorizer(dimensions=64)
        v1 = vec.vectorize("Operating system control plane")
        v2 = vec.vectorize("Operating system control plane")
        self.assertEqual(len(v1), 64)
        self.assertEqual(v1, v2)
        sim = vec.cosine_similarity(v1, v2)
        self.assertAlmostEqual(sim, 1.0, places=4)

    def test_get_vectorizer_factory(self):
        """Verify get_vectorizer factory handles hash and provider names."""
        v_hash = get_vectorizer("hash", dimensions=32)
        self.assertIsInstance(v_hash, HashTextVectorizer)
        self.assertEqual(v_hash.dimensions, 32)

        v_openai = get_vectorizer("openai", dimensions=32)
        self.assertIsInstance(v_openai, DenseEmbeddingVectorizer)

    async def test_dense_embedding_graceful_fallback(self):
        """Verify DenseEmbeddingVectorizer degrades gracefully to hash vectorizer on error."""
        dense_vec = DenseEmbeddingVectorizer(
            provider="openai",
            api_key="", # Missing key
            dimensions=64
        )
        # Should gracefully return valid unit vector without throwing
        v = await dense_vec.avectorize("Autonomous agent execution")
        self.assertEqual(len(v), 64)
        self.assertGreater(sum(abs(x) for x in v), 0.0)

    async def test_l3_semantic_store_with_custom_vectorizer(self):
        """Verify L3SemanticStore works seamlessly with pluggable vectorizer."""
        custom_vec = HashTextVectorizer(dimensions=64)
        store = L3SemanticStore(db_path=settings.workspace_root / "test_pluggable_l3.db", vectorizer=custom_vec)
        
        await store.clear()
        entry = await store.add("Contextual knowledge base turn", metadata={"test": True})
        self.assertIsNotNone(entry)
        
        results = await store.search("knowledge base", top_k=1)
        self.assertEqual(len(results), 1)
        self.assertGreater(results[0].relevance_score, 0.1)
        await store.clear()

    def test_cost_estimator_with_pluggable_vectorizer(self):
        """Verify CostEstimator functions with injected BaseTextVectorizer."""
        custom_vec = HashTextVectorizer(dimensions=64)
        estimator = CostEstimator(vectorizer=custom_vec)
        est = estimator.estimate(role="coder", instruction="Write binary search in Python")
        self.assertGreater(est.predicted_tokens_p50, 0)
        self.assertGreaterEqual(est.predicted_tokens_p90, est.predicted_tokens_p50)

    # -------------------------------------------------------------
    # 3. Pluggable Code Runner Sandbox Tests
    # -------------------------------------------------------------
    def test_get_code_runner_factory(self):
        """Verify get_code_runner factory selects local or docker runner."""
        local_runner = get_code_runner("local")
        self.assertIsInstance(local_runner, IsolatedCodeRunner)

        docker_runner = get_code_runner("docker")
        self.assertIsInstance(docker_runner, DockerIsolatedRunner)

    async def test_docker_runner_graceful_fallback_when_daemon_unavailable(self):
        """Verify DockerIsolatedRunner gracefully executes via local sandbox if docker fails."""
        runner = DockerIsolatedRunner(image="python:3.11-slim", timeout_seconds=5.0)

        real_subprocess_exec = asyncio.create_subprocess_exec

        async def conditional_subprocess_exec(*args, **kwargs):
            if args and args[0] == "/fake/bin/docker":
                raise RuntimeError("Docker daemon connection refused")
            return await real_subprocess_exec(*args, **kwargs)

        with patch("shutil.which", return_value="/fake/bin/docker"):
            with patch("asyncio.create_subprocess_exec", side_effect=conditional_subprocess_exec):
                result = await runner.run_python("print('Recovered via host sandbox')")
                self.assertEqual(result.exit_code, 0)
                self.assertIn("Recovered via host sandbox", result.stdout)
                self.assertIn("Container runtime unavailable", result.stderr)

    async def test_sys_exec_python_with_injected_runner(self):
        """Verify SysExecPython syscall accepts pluggable custom runner."""
        mock_kernel = MagicMock()
        mock_kernel.hitl_manager.create_request.return_value = MagicMock(resolved=True, approved=True)

        mock_runner = AsyncMock(spec=BaseCodeRunner)
        mock_runner.run_python.return_value = ExecutionResult(
            stdout="Injected Runner Output",
            stderr="",
            exit_code=0,
            duration_ms=15.0,
            timed_out=False
        )

        syscall = SysExecPython(kernel=mock_kernel, runner=mock_runner)
        pcb = ProcessControlBlock(name="test-proc", role="coder")

        res = await syscall.execute(pcb=pcb, code="print('hello')")
        self.assertTrue(res.success)
        self.assertEqual(res.data["stdout"], "Injected Runner Output")
        mock_runner.run_python.assert_called_once()
