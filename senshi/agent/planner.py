"""
AgentPlanner — LLM-based action selection for the pentest agent.

Asks the LLM "what should we test next?" given the accumulated context.
"""

from __future__ import annotations

from typing import Any

from senshi.agent.actions import Action
from senshi.agent.context import PentestContext
from senshi.ai.brain import Brain
from senshi.ai.prompts.agent import (
    ACTION_SELECTION_PROMPT,
    PENTEST_AGENT_SYSTEM_PROMPT,
)
from senshi.utils.logger import get_logger

logger = get_logger("senshi.agent.planner")


class AgentPlanner:
    """LLM-based action planner — decides what the agent should do next."""

    def __init__(self, brain: Brain, budget: int = 0) -> None:
        self.brain = brain
        self.budget = budget  # 0 = unlimited
        self._calls = 0

    async def next_action(self, context: PentestContext) -> Action:
        """
        Ask the LLM to choose the next action.

        Returns Action(type="done") if:
        - LLM decides testing is complete
        - Budget is exhausted
        - All endpoints have been thoroughly tested
        """
        # Budget check
        if self.budget and self._calls >= self.budget:
            logger.info(f"LLM budget exhausted ({self.budget} calls)")
            return Action(type="done", reasoning="LLM budget exhausted")

        # Check if there's anything left to test
        untested = [
            ep for ep in context.endpoints
            if not context._is_fully_tested(ep)
        ]
        if not untested and context.iteration > 5:
            return Action(type="done", reasoning="All endpoints thoroughly tested")

        # Build prompt
        user_prompt = ACTION_SELECTION_PROMPT.format(
            context_summary=context.get_summary(),
            blocked_combinations=context.blocked_summary,
        )

        try:
            self._calls += 1
            context.llm_calls += 1

            result = await self.brain.async_think(
                system_prompt=PENTEST_AGENT_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
                temperature=0.3,  # Slightly creative for diverse action selection
            )

            if isinstance(result, dict):
                action = Action.from_dict(result)
                logger.debug(f"Planner chose: {action.type} — {action.reasoning}")
                return action

            return Action(type="done", reasoning="Failed to parse LLM response")

        except Exception as e:
            logger.warning(f"Planner error: {e}")
            # On error, try the next untested endpoint with a safe action
            if untested:
                return Action(
                    type="explore_endpoint",
                    params={"url": untested[0]["url"]},
                    reasoning=f"Fallback: exploring untested endpoint (planner error: {e})",
                )
            return Action(type="done", reasoning=f"Planner failed: {e}")
