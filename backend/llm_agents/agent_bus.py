"""
AgentBus — Thread-safe coordination hub for the 4-agent analysis pipeline.

Agents post their findings, read each other's interim results, and broadcast
progress updates. The OrchestratorAgent polls this bus to merge all results.
"""

import threading
import logging
import time
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)

AGENT_NAMES = ['security', 'quality', 'dependency', 'orchestrator']


class AgentBus:
    """
    Shared message bus for inter-agent coordination.

    Each agent can:
      - post(agent_name, key, value)  → publish a finding or partial result
      - read(agent_name, key)         → read another agent's data
      - broadcast_progress(...)       → update the shared progress log
      - wait_for(agents, timeout)     → block until listed agents finish
    """

    def __init__(self, uid: str):
        self.uid = uid
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {n: {} for n in AGENT_NAMES}
        self._status: Dict[str, str] = {n: 'waiting' for n in AGENT_NAMES}
        self._progress: Dict[str, int] = {n: 0 for n in AGENT_NAMES}
        self._log: List[Dict[str, Any]] = []  # ordered event log
        self._finish_events: Dict[str, threading.Event] = {
            n: threading.Event() for n in AGENT_NAMES
        }
        self._on_progress_callbacks: List[Callable] = []

    # ── Publishing ──────────────────────────────────────────────────────────

    def post(self, agent_name: str, key: str, value: Any):
        """Write a key/value result from an agent."""
        with self._lock:
            if agent_name not in self._data:
                self._data[agent_name] = {}
            self._data[agent_name][key] = value
        logger.debug(f"[AgentBus] {agent_name} posted '{key}'")

    def read(self, agent_name: str, key: str, default=None) -> Any:
        """Read another agent's published value (thread-safe)."""
        with self._lock:
            return self._data.get(agent_name, {}).get(key, default)

    def read_all(self, agent_name: str) -> Dict[str, Any]:
        """Read all data published by an agent."""
        with self._lock:
            return dict(self._data.get(agent_name, {}))

    # ── Status & Progress ───────────────────────────────────────────────────

    def set_status(self, agent_name: str, status: str, progress: int = None, message: str = ''):
        """
        Update an agent's status.
        status: 'waiting' | 'running' | 'done' | 'error'
        """
        with self._lock:
            self._status[agent_name] = status
            if progress is not None:
                self._progress[agent_name] = progress
            event = {
                'ts': time.time(),
                'agent': agent_name,
                'status': status,
                'progress': progress or self._progress.get(agent_name, 0),
                'message': message,
            }
            self._log.append(event)
        logger.info(f"[AgentBus] {agent_name} → {status} ({progress}%) — {message}")

        if status == 'done':
            self._finish_events[agent_name].set()

        # Call registered callbacks (e.g. update analysis_status)
        for cb in self._on_progress_callbacks:
            try:
                cb(agent_name, status, progress, message)
            except Exception as exc:
                logger.warning(f"[AgentBus] Progress callback error: {exc}")

    def mark_done(self, agent_name: str, message: str = 'Complete'):
        self.set_status(agent_name, 'done', 100, message)

    def mark_error(self, agent_name: str, error: str):
        self.set_status(agent_name, 'error', None, error)
        self._finish_events[agent_name].set()  # unblock waiters

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a JSON-serializable snapshot of the current bus state."""
        with self._lock:
            return {
                'uid': self.uid,
                'agents': {
                    name: {
                        'status': self._status.get(name, 'waiting'),
                        'progress': self._progress.get(name, 0),
                    }
                    for name in AGENT_NAMES
                },
                'log': list(self._log[-20:]),  # last 20 events
                'overall_progress': self._overall_progress(),
            }

    def _overall_progress(self) -> int:
        """Weighted average progress across all agents."""
        weights = {'security': 30, 'quality': 30, 'dependency': 15, 'orchestrator': 25}
        total_weight = sum(weights.values())
        weighted = sum(
            self._progress.get(n, 0) * w
            for n, w in weights.items()
        )
        return int(weighted / total_weight)

    # ── Coordination ────────────────────────────────────────────────────────

    def wait_for(self, agents: List[str], timeout: float = 180.0) -> bool:
        """
        Block until all listed agents have finished (done or error).
        Returns True if all finished within timeout, False otherwise.
        """
        deadline = time.time() + timeout
        for agent in agents:
            remaining = deadline - time.time()
            if remaining <= 0:
                logger.warning(f"[AgentBus] wait_for timed out waiting for {agent}")
                return False
            finished = self._finish_events[agent].wait(timeout=remaining)
            if not finished:
                logger.warning(f"[AgentBus] Timeout waiting for agent '{agent}'")
                return False
        return True

    def register_progress_callback(self, cb: Callable):
        """Register a callback(agent_name, status, progress, message) for live updates."""
        self._on_progress_callbacks.append(cb)

    # ── Merge helpers (used by Orchestrator) ───────────────────────────────

    def collect_findings(self) -> Dict[str, List[Dict]]:
        """Collect all findings posted by security + quality + dependency agents."""
        result = {}
        for agent in ['security', 'quality', 'dependency']:
            findings = self.read(agent, 'findings') or []
            result[agent] = findings
        return result

    def get_agent_log(self) -> List[Dict]:
        with self._lock:
            return list(self._log)
