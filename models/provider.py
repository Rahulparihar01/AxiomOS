import asyncio
import json
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Callable, Dict, List, Optional
import httpx
from pydantic import BaseModel, Field
from config.settings import settings

class ToolCallRequest(BaseModel):
    id: str
    name: str
    arguments: Dict[str, Any]

class ModelResponse(BaseModel):
    content: Optional[str] = None
    tool_calls: List[ToolCallRequest] = Field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

class BaseModelProvider(ABC):
    """Abstract interface for LLM compute backends."""
    
    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Callable[[str], Any]] = None
    ) -> ModelResponse:
        pass

    async def generate_stream(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> AsyncIterator[str]:
        """
        Stream incremental text token chunks from the compute backend.
        Default implementation calls generate() and yields the content in word chunks.
        """
        resp = await self.generate(system_prompt=system_prompt, messages=messages, tools=tools)
        if resp.content:
            chunks = resp.content.split(" ")
            for i, chunk in enumerate(chunks):
                yield chunk + (" " if i < len(chunks) - 1 else "")
                await asyncio.sleep(0.005)

    async def aclose(self) -> None:
        """Release underlying network and connection pool resources."""
        pass

class MockProvider(BaseModelProvider):
    """
    Deterministic mock provider for zero-cost testing and offline development.
    Simulates multi-step reasoning: first issues a syscall, then generates a final answer.
    """
    def __init__(self):
        self._call_counter = 0

    def _compute_mock_response(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> ModelResponse:
        self._call_counter += 1
        last_msg = messages[-1]["content"] if messages else ""

        # Check if the previous message was a tool result
        if messages and messages[-1].get("role") == "tool":
            return ModelResponse(
                content=f"Task complete. Processed tool output successfully: {messages[-1].get('content')}",
                tool_calls=[],
                prompt_tokens=120,
                completion_tokens=35,
                total_tokens=155
            )

        # First step: simulate an agent calling a tool, strictly honoring allocated tool permissions
        allowed_names = {t.get("name") for t in tools} if tools else set()
        can_call = lambda name: (not tools) or (name in allowed_names)

        if ("sandbox" in last_msg.lower() or "python" in last_msg.lower()) and can_call("sys_exec_python"):
            return ModelResponse(
                content="Executing isolated python script inside ephemeral sandbox.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_sandbox",
                        name="sys_exec_python",
                        arguments={"code": "print(sum(range(1, 101)))"}
                    )
                ],
                prompt_tokens=90,
                completion_tokens=30,
                total_tokens=120
            )
        elif ("plan" in last_msg.lower() or "dag" in last_msg.lower()) and can_call("sys_plan_register_subtask"):
            return ModelResponse(
                content="Decomposing instruction into ordered DAG subtask via sys_plan_register_subtask.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_plan",
                        name="sys_plan_register_subtask",
                        arguments={
                            "subtask_id": "subtask-101",
                            "description": "Initialize database connection pool and verify endpoints",
                            "dependencies": []
                        }
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        elif ("verdict" in last_msg.lower() or "audit" in last_msg.lower()) and can_call("sys_audit_record_verdict"):
            return ModelResponse(
                content="Auditing target process artifacts and committing audit verdict via sys_audit_record_verdict.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_verdict",
                        name="sys_audit_record_verdict",
                        arguments={
                            "target_pid": "proc-child-001",
                            "approved": True,
                            "comments": "Automated auditor verified output correctness."
                        }
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        elif ("artifact" in last_msg.lower() or "synthesize" in last_msg.lower()) and can_call("sys_code_record_artifact"):
            return ModelResponse(
                content="Synthesizing module and recording artifact via sys_code_record_artifact.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_artifact",
                        name="sys_code_record_artifact",
                        arguments={
                            "filename": "algo.py",
                            "code": "def run_algo(): return sorted([3, 1, 2])"
                        }
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        elif ("research" in last_msg.lower()) and can_call("sys_research_record_finding"):
            return ModelResponse(
                content="Recording verified research fact via sys_research_record_finding.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_finding",
                        name="sys_research_record_finding",
                        arguments={
                            "source_url": "https://ai-os.org/docs/kernel",
                            "topic": "kernel_architecture",
                            "content": "AxiomOS microkernel provides capability security and deterministic replay."
                        }
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        elif ("resolve" in last_msg.lower() or "arbitrat" in last_msg.lower()) and can_call("sys_conflict_record_resolution"):
            return ModelResponse(
                content="Arbitrating memory conflict and recording resolution via sys_conflict_record_resolution.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_resolution",
                        name="sys_conflict_record_resolution",
                        arguments={
                            "key": "system.status",
                            "chosen_value": "healthy",
                            "rationale": "Arbitrated based on consensus cross-validation."
                        }
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        elif ("kill" in last_msg.lower() or "terminate" in last_msg.lower()) and can_call("sys_proc_kill"):
            return ModelResponse(
                content="Issuing sys_proc_kill to terminate target process and its child hierarchy.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_kill",
                        name="sys_proc_kill",
                        arguments={"target_pid": "proc-target-abort", "cascade": True}
                    )
                ],
                prompt_tokens=85,
                completion_tokens=30,
                total_tokens=115
            )
        elif ("audit" in last_msg.lower() or "review" in last_msg.lower() or "verify" in last_msg.lower()) and can_call("sys_bb_read"):
            return ModelResponse(
                content="Inspecting workspace and blackboard state to issue audit verification verdict.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_review",
                        name="sys_bb_read",
                        arguments={"topic": "system_audit", "key": "audit_status"}
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        elif ("calc" in last_msg.lower() or "calculate" in last_msg.lower() or "math" in last_msg.lower()) and can_call("sys_calc"):
            return ModelResponse(
                content="I will evaluate this calculation using the kernel sys_calc tool.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_1",
                        name="sys_calc",
                        arguments={"expression": "sqrt(144) + 25 * 3"}
                    )
                ],
                prompt_tokens=80,
                completion_tokens=40,
                total_tokens=120
            )
        elif ("read" in last_msg.lower() or "file" in last_msg.lower()) and can_call("sys_fs_read"):
            return ModelResponse(
                content="Reading the requested workspace file via sys_fs_read.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_2",
                        name="sys_fs_read",
                        arguments={"filepath": "requirements.txt"}
                    )
                ],
                prompt_tokens=90,
                completion_tokens=45,
                total_tokens=135
            )
        elif ("persist" in last_msg.lower() or "store" in last_msg.lower() or "memory" in last_msg.lower()) and can_call("sys_mem_store"):
            return ModelResponse(
                content="Persisting audit configuration and state parameters into MMU archival memory.",
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_mem",
                        name="sys_mem_store",
                        arguments={"key": "audit_config", "value": "System audit configuration parameters initialized"}
                    )
                ],
                prompt_tokens=85,
                completion_tokens=35,
                total_tokens=120
            )
        else:
            return ModelResponse(
                content="AxiomOS agent processed your request successfully using autonomous reasoning.",
                tool_calls=[],
                prompt_tokens=50,
                completion_tokens=25,
                total_tokens=75
            )

    async def generate_stream(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> AsyncIterator[str]:
        """Yield incremental simulated token chunks with realistic async pauses."""
        resp = self._compute_mock_response(system_prompt, messages, tools)
        if resp.content:
            words = resp.content.split(" ")
            for i, w in enumerate(words):
                chunk = w + (" " if i < len(words) - 1 else "")
                yield chunk
                await asyncio.sleep(0.02)

    async def generate(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Callable[[str], Any]] = None
    ) -> ModelResponse:
        resp = self._compute_mock_response(system_prompt, messages, tools)
        if on_token and resp.content:
            words = resp.content.split(" ")
            for i, w in enumerate(words):
                chunk = w + (" " if i < len(words) - 1 else "")
                try:
                    res = on_token(chunk)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    pass
                await asyncio.sleep(0.02)
        return resp



class GeminiProvider(BaseModelProvider):
    """Google Gemini REST API adapter with dynamic function calling support."""
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model = model
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or initialize persistent pooled HTTP client."""
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=settings.http_pool_max_keepalive,
                max_connections=settings.http_pool_max_connections
            )
            self._client = httpx.AsyncClient(timeout=settings.http_timeout_seconds, limits=limits)
        return self._client

    async def aclose(self) -> None:
        """Close connection pool cleanly."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _build_payload(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        contents = []
        for msg in messages:
            role = msg.get("role")
            if role == "tool":
                contents.append({
                    "role": "user",
                    "parts": [{
                        "functionResponse": {
                            "name": msg.get("name", "tool"),
                            "response": {"result": msg.get("content", "")}
                        }
                    }]
                })
            elif role == "assistant" and msg.get("tool_calls"):
                parts = []
                if msg.get("content"):
                    parts.append({"text": str(msg["content"])})
                for tc in msg["tool_calls"]:
                    parts.append({
                        "functionCall": {
                            "name": tc.get("name", ""),
                            "args": tc.get("arguments", {})
                        }
                    })
                contents.append({"role": "model", "parts": parts})
            else:
                gemini_role = "user" if role in ["user", "system"] else "model"
                contents.append({
                    "role": gemini_role,
                    "parts": [{"text": str(msg.get("content", ""))}]
                })

        payload: Dict[str, Any] = {
            "contents": contents,
            "systemInstruction": {"parts": [{"text": system_prompt}]}
        }

        # Convert tools to Gemini functionDeclarations
        if tools:
            func_decls = []
            for t in tools:
                if t.get("type") == "function":
                    fn = t.get("function", {})
                    func_decls.append({
                        "name": fn.get("name", ""),
                        "description": fn.get("description", ""),
                        "parameters": fn.get("parameters", {"type": "object", "properties": {}})
                    })
                elif "name" in t:
                    func_decls.append({
                        "name": t.get("name", ""),
                        "description": t.get("description", ""),
                        "parameters": t.get("parameters", {"type": "object", "properties": {}})
                    })
            if func_decls:
                payload["tools"] = [{"functionDeclarations": func_decls}]
        return payload

    async def generate_stream(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> AsyncIterator[str]:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured in environment or settings.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:streamGenerateContent?alt=sse&key={self.api_key}"
        payload = self._build_payload(system_prompt, messages, tools)
        client = await self.get_client()
        async with client.stream("POST", url, json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    raw = line[6:].strip()
                    if not raw:
                        continue
                    try:
                        chunk_data = json.loads(raw)
                        parts = chunk_data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                        for p in parts:
                            if "text" in p:
                                yield p["text"]
                    except Exception:
                        pass

    async def generate(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Callable[[str], Any]] = None
    ) -> ModelResponse:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured in environment or settings.")

        url = f"{self.base_url}?key={self.api_key}"
        payload = self._build_payload(system_prompt, messages, tools)

        client = await self.get_client()
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

        try:
            candidate = data["candidates"][0]
            parts = candidate.get("content", {}).get("parts", [])
            text_parts = []
            tool_calls: List[ToolCallRequest] = []

            for part in parts:
                if "text" in part:
                    text_parts.append(part["text"])
                if "functionCall" in part:
                    fc = part["functionCall"]
                    tool_calls.append(
                        ToolCallRequest(
                            id=f"call_{fc.get('name', 'tool')}",
                            name=fc.get("name", ""),
                            arguments=fc.get("args", {})
                        )
                    )

            usage = data.get("usageMetadata", {})
            full_text = " ".join(text_parts) if text_parts else None
            if on_token and full_text:
                for w in full_text.split(" "):
                    chunk = w + " "
                    try:
                        res = on_token(chunk)
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception:
                        pass
                    await asyncio.sleep(0.005)

            return ModelResponse(
                content=full_text,
                tool_calls=tool_calls,
                prompt_tokens=usage.get("promptTokenCount", 0),
                completion_tokens=usage.get("candidatesTokenCount", 0),
                total_tokens=usage.get("totalTokenCount", 0)
            )
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Unexpected response format from Gemini API: {str(e)}")

class OpenAIProvider(BaseModelProvider):
    """OpenAI compatible REST API adapter with native function tool calling."""
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or initialize persistent pooled HTTP client."""
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=settings.http_pool_max_keepalive,
                max_connections=settings.http_pool_max_connections
            )
            self._client = httpx.AsyncClient(timeout=settings.http_timeout_seconds, limits=limits)
        return self._client

    async def aclose(self) -> None:
        """Close connection pool cleanly."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _build_request(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> tuple[Dict[str, Any], Dict[str, str]]:
        formatted_messages = [{"role": "system", "content": system_prompt}]
        for msg in messages:
            f_msg: Dict[str, Any] = {"role": msg.get("role", "user")}
            if msg.get("content") is not None:
                f_msg["content"] = str(msg["content"])
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                f_msg["tool_calls"] = [
                    {
                        "id": tc.get("id", "call_id"),
                        "type": "function",
                        "function": {
                            "name": tc.get("name", ""),
                            "arguments": json.dumps(tc.get("arguments", {})) if isinstance(tc.get("arguments"), dict) else str(tc.get("arguments", "{}"))
                        }
                    }
                    for tc in msg["tool_calls"]
                ]
            elif msg.get("role") == "tool":
                f_msg["tool_call_id"] = msg.get("tool_call_id", "")
                if "name" in msg:
                    f_msg["name"] = msg["name"]
            formatted_messages.append(f_msg)

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": formatted_messages
        }

        if tools:
            formatted_tools = []
            for t in tools:
                if t.get("type") == "function":
                    formatted_tools.append(t)
                else:
                    formatted_tools.append({
                        "type": "function",
                        "function": {
                            "name": t.get("name", ""),
                            "description": t.get("description", ""),
                            "parameters": t.get("parameters", {"type": "object", "properties": {}})
                        }
                    })
            payload["tools"] = formatted_tools

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        return payload, headers

    async def generate_stream(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> AsyncIterator[str]:
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not configured in environment.")

        payload, headers = self._build_request(system_prompt, messages, tools)
        payload["stream"] = True

        client = await self.get_client()
        async with client.stream("POST", f"{self.base_url}/chat/completions", json=payload, headers=headers) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    raw = line[6:].strip()
                    if raw == "[DONE]" or not raw:
                        continue
                    try:
                        chunk = json.loads(raw)
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content")
                        if content:
                            yield content
                    except Exception:
                        pass

    async def generate(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Callable[[str], Any]] = None
    ) -> ModelResponse:
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not configured in environment.")

        payload, headers = self._build_request(system_prompt, messages, tools)

        client = await self.get_client()
        resp = await client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        choice = data["choices"][0]["message"]
        tool_calls: List[ToolCallRequest] = []
        if "tool_calls" in choice and choice["tool_calls"]:
            for tc in choice["tool_calls"]:
                func = tc.get("function", {})
                func_name = func.get("name", "")
                raw_args = func.get("arguments", "{}")
                try:
                    parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except Exception:
                    parsed_args = {}
                tool_calls.append(
                    ToolCallRequest(
                        id=tc.get("id", f"call_{func_name}"),
                        name=func_name,
                        arguments=parsed_args
                    )
                )

        usage = data.get("usage", {})
        content_text = choice.get("content")
        if on_token and content_text:
            for w in content_text.split(" "):
                chunk = w + " "
                try:
                    res = on_token(chunk)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    pass
                await asyncio.sleep(0.005)

        return ModelResponse(
            content=content_text,
            tool_calls=tool_calls,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0)
        )

def get_provider(provider_type: str, settings_obj: Any, model_name: Optional[str] = None) -> BaseModelProvider:
    """Factory function for instantiating model providers."""
    provider_type = provider_type.lower()
    selected_model = model_name or settings_obj.model_name
    if provider_type == "mock":
        return MockProvider()
    elif provider_type == "gemini":
        return GeminiProvider(api_key=settings_obj.gemini_api_key, model=selected_model)
    elif provider_type == "openai":
        return OpenAIProvider(api_key=settings_obj.openai_api_key, model=selected_model)
    elif provider_type == "ollama":
        return OpenAIProvider(
            api_key="ollama",
            model=selected_model,
            base_url=f"{settings_obj.ollama_base_url}/v1"
        )
    else:
        raise ValueError(f"Unsupported provider: '{provider_type}'. Supported: mock, gemini, openai, ollama")
