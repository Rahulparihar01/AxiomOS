import asyncio
import json
import unittest
from typing import Any, Dict, List, Optional
from starlette.testclient import TestClient

from config.settings import settings
from kernel.event_loop import Kernel
from kernel.process import PriorityLevel, ProcessState, ProcessControlBlock
from models.provider import BaseModelProvider, MockProvider, ModelResponse
from models.router import AdaptiveModelRouter
from server.app import create_app

class CustomDummyProvider(BaseModelProvider):
    """Minimal provider implementing only generate() to test BaseModelProvider default stream fallback."""
    async def generate(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Any] = None
    ) -> ModelResponse:
        return ModelResponse(
            content="Alpha Beta Gamma Delta Epsilon",
            tool_calls=[],
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15
        )

class TestTokenStreaming(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying GAP-12 real-time incremental token streaming across providers, kernel, and WebSockets."""

    async def test_mock_provider_generate_stream(self):
        """Verify MockProvider.generate_stream() yields incremental token chunks."""
        provider = MockProvider()
        chunks = []
        async for chunk in provider.generate_stream(
            system_prompt="System instructions",
            messages=[{"role": "user", "content": "Hello AI-OS"}]
        ):
            self.assertIsInstance(chunk, str)
            self.assertTrue(len(chunk) > 0)
            chunks.append(chunk)

        self.assertGreater(len(chunks), 1)
        full_text = "".join(chunks).strip()
        self.assertIn("AxiomOS agent processed your request successfully", full_text)

    async def test_mock_provider_on_token_callback(self):
        """Verify MockProvider.generate() fires on_token callback while returning full ModelResponse."""
        provider = MockProvider()
        received_tokens = []

        def token_listener(chunk: str):
            received_tokens.append(chunk)

        resp = await provider.generate(
            system_prompt="Test",
            messages=[{"role": "user", "content": "Execute agent reasoning"}],
            on_token=token_listener
        )

        self.assertIsInstance(resp, ModelResponse)
        self.assertIsNotNone(resp.content)
        self.assertGreater(len(received_tokens), 0)
        self.assertEqual("".join(received_tokens).strip(), resp.content.strip())
        self.assertGreater(resp.total_tokens, 0)

    async def test_base_provider_default_stream_fallback(self):
        """Verify BaseModelProvider default generate_stream() properly chunks content."""
        provider = CustomDummyProvider()
        chunks = []
        async for chunk in provider.generate_stream(
            system_prompt="Test",
            messages=[{"role": "user", "content": "Ping"}]
        ):
            chunks.append(chunk)

        self.assertEqual(len(chunks), 5)
        self.assertEqual("".join(chunks).strip(), "Alpha Beta Gamma Delta Epsilon")

    async def test_model_router_fallback_streaming_callback(self):
        """Verify AdaptiveModelRouter forwards on_token callback through primary and fallback paths."""
        class FailingPrimary(BaseModelProvider):
            async def generate(self, system_prompt, messages, tools=None, on_token=None):
                raise RuntimeError("503 Backend Model Unavailable")

        fallback = MockProvider()
        router = AdaptiveModelRouter(
            reasoning_provider=FailingPrimary(),
            fast_provider=FailingPrimary(),
            fallback_provider=fallback,
            failure_threshold=1
        )

        pcb = ProcessControlBlock(
            pid="proc-test-router",
            name="test_agent",
            priority=PriorityLevel.NORMAL
        )

        streamed_deltas = []
        resp = await router.generate_with_fallback(
            pcb=pcb,
            system_prompt="Test prompt",
            messages=[{"role": "user", "content": "Summarize status"}],
            on_token=lambda d: streamed_deltas.append(d)
        )

        self.assertIsInstance(resp, ModelResponse)
        self.assertGreater(len(streamed_deltas), 0)
        self.assertEqual("".join(streamed_deltas).strip(), resp.content.strip())
        self.assertTrue(router.circuit_open)

    async def test_kernel_token_listener_integration(self):
        """Verify Kernel.add_token_listener receives token stream deltas during process execution step."""
        kernel = Kernel(provider_name="mock")
        received_events = []

        def token_sink(pid: str, delta: str):
            received_events.append((pid, delta))

        kernel.add_token_listener(token_sink)

        pcb = kernel.spawn_process(
            name="stream_test_agent",
            task_instruction="Autonomous task requiring multi-token reasoning",
            priority=PriorityLevel.HIGH
        )

        # Execute single reasoning step
        await kernel._execute_process_step(pcb)

        self.assertGreater(len(received_events), 0)
        pids = {ev[0] for ev in received_events}
        self.assertIn(pcb.pid, pids)
        accumulated_text = "".join(ev[1] for ev in received_events)
        self.assertIn("AxiomOS agent processed your request successfully", accumulated_text)

    async def test_websocket_token_streaming_endpoint(self):
        """Verify connected WebSocket client receives token_chunk frames in real time."""
        kernel = Kernel(provider_name="mock")
        app = create_app(kernel)
        client = TestClient(app)

        with client.websocket_connect("/ws/stream") as ws:
            # Send keepalive ping to confirm connection
            ws.send_text("ping")
            pong = ws.receive_json()
            self.assertEqual(pong.get("type"), "pong")

            # Broadcast synthetic token chunk directly via kernel
            kernel.notify_token(pid="proc-ws-stream-1", delta="StreamingTokenDelta ")

            msg = ws.receive_json()
            self.assertEqual(msg.get("type"), "token_chunk")
            self.assertEqual(msg.get("pid"), "proc-ws-stream-1")
            self.assertEqual(msg.get("delta"), "StreamingTokenDelta ")

            # Now run a process step and observe live agent token deltas arriving on the WebSocket
            pcb = kernel.spawn_process(
                name="ws_proc_agent",
                task_instruction="Process live agent work",
                priority=PriorityLevel.NORMAL
            )

            # Let kernel process the step
            await kernel._execute_process_step(pcb)

            # Collect incoming websocket frames until process completed
            token_deltas = []
            for _ in range(30):
                raw_msg = ws.receive_text()
                frame = json.loads(raw_msg)
                if frame.get("type") == "token_chunk" and frame.get("pid") == pcb.pid:
                    token_deltas.append(frame.get("delta", ""))
                elif frame.get("type") == "process_update":
                    p_state = frame.get("process", {}).get("state")
                    if p_state == ProcessState.COMPLETED.value and len(token_deltas) > 0:
                        break

            self.assertGreater(len(token_deltas), 0)
            self.assertIn("AxiomOS agent processed", "".join(token_deltas))

if __name__ == "__main__":
    unittest.main()
