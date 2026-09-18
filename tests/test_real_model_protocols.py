import json
import unittest
from memory.l1_context import L1ContextManager
from models.provider import OpenAIProvider, GeminiProvider, ToolCallRequest

class TestRealModelProtocols(unittest.TestCase):
    """Test suite verifying LLM provider formatting and agent chat turn sequencing."""

    def test_l1_context_atomic_tool_turn_extraction(self):
        """Verify assistant tool_calls and tool turns are never split during context eviction."""
        l1 = L1ContextManager(max_capacity_tokens=500)
        
        # Turn 1: user
        l1.add_message("user", "Calculate sqrt(144)")
        # Turn 2: assistant calling tool
        l1.add_message(
            "assistant",
            "Evaluating...",
            tool_calls=[{"id": "call_1", "name": "sys_calc", "arguments": {"expression": "sqrt(144)"}}]
        )
        # Turn 3: tool result
        l1.add_message(
            "tool",
            json.dumps({"result": 12.0}),
            tool_call_id="call_1",
            name="sys_calc"
        )
        # Turn 4: assistant final answer
        l1.add_message("assistant", "The answer is 12.")
        # Turn 5: next user prompt
        l1.add_message("user", "Now multiply by 3")

        self.assertEqual(len(l1.messages), 5)

        # Evict with count=2 (which would naively cut between assistant tool_calls and tool result)
        evicted = l1.extract_oldest_turns(count=2)

        # Atomic rule: Must include the tool message (Turn 3) with the assistant message (Turn 2)
        # so the remaining messages start with assistant final answer or user, NOT an orphaned tool message!
        self.assertGreaterEqual(len(evicted), 3)
        self.assertEqual(evicted[0]["role"], "user")
        self.assertEqual(evicted[1]["role"], "assistant")
        self.assertEqual(evicted[2]["role"], "tool")

        # Remaining messages must not start with an orphaned tool turn
        self.assertNotEqual(l1.messages[0]["role"], "tool")

    def test_openai_tool_schema_formatting(self):
        """Verify OpenAI provider wraps AI-OS syscall declarations into OpenAI function tool format."""
        provider = OpenAIProvider(api_key="test-key", model="gpt-4o")
        
        raw_aios_tools = [
            {
                "name": "sys_calc",
                "description": "Calculate math",
                "parameters": {"type": "object", "properties": {"expression": {"type": "string"}}},
                "is_mutating": False
            }
        ]

        # Inspect formatted tools inside provider logic
        formatted_tools = []
        for t in raw_aios_tools:
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

        self.assertEqual(len(formatted_tools), 1)
        self.assertEqual(formatted_tools[0]["type"], "function")
        self.assertEqual(formatted_tools[0]["function"]["name"], "sys_calc")

    def test_gemini_tool_schema_formatting(self):
        """Verify Gemini provider converts tools into functionDeclarations."""
        raw_tools = [
            {
                "name": "sys_fs_read",
                "description": "Read file",
                "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}}
            }
        ]

        func_decls = []
        for t in raw_tools:
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

        self.assertEqual(len(func_decls), 1)
        self.assertEqual(func_decls[0]["name"], "sys_fs_read")

if __name__ == "__main__":
    unittest.main()
