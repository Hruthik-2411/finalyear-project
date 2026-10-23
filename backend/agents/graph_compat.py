"""Use the real LangGraph when installed (normal case); otherwise a tiny stand-in with the
same API subset (StateGraph / add_node / add_edge / add_conditional_edges / compile /
invoke). The stand-in exists only so the project can run in sandboxes without LangGraph."""
from __future__ import annotations

try:  # pragma: no cover - depends on environment
    from langgraph.graph import END, START, StateGraph  # type: ignore

    LANGGRAPH_AVAILABLE = True
except Exception:  # pragma: no cover
    LANGGRAPH_AVAILABLE = False
    START, END = "__start__", "__end__"

    class _Compiled:
        def __init__(self, nodes, edges, cond):
            self.nodes, self.edges, self.cond = nodes, edges, cond

        def invoke(self, state: dict, config: dict | None = None) -> dict:
            limit = (config or {}).get("recursion_limit", 25)
            state = dict(state)
            current = self.edges[START]
            steps = 0
            while current != END:
                steps += 1
                if steps > limit:
                    raise RuntimeError("recursion limit reached")
                update = self.nodes[current](state) or {}
                state.update(update)
                if current in self.cond:
                    router, mapping = self.cond[current]
                    key = router(state)
                    current = mapping[key] if mapping else key
                else:
                    current = self.edges[current]
            return state

    class StateGraph:  # type: ignore[no-redef]
        def __init__(self, schema=None):
            self.nodes, self.edges, self.cond = {}, {}, {}

        def add_node(self, name, fn):
            self.nodes[name] = fn

        def add_edge(self, a, b):
            self.edges[a] = b

        def add_conditional_edges(self, src, router, mapping=None):
            self.cond[src] = (router, mapping)

        def compile(self):
            return _Compiled(self.nodes, self.edges, self.cond)
