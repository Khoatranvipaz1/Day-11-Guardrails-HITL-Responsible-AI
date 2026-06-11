"""
Lab 11 — Helper Utilities
"""
from google.genai import types


def is_quota_error(error: Exception) -> bool:
    """Return True when Gemini rejected a request because quota was exhausted."""
    message = str(error).upper()
    return "429" in message and (
        "RESOURCE_EXHAUSTED" in message or "QUOTA EXCEEDED" in message
    )


def concise_api_error(error: Exception) -> str:
    """Convert verbose SDK exceptions into a short terminal-friendly message."""
    if is_quota_error(error):
        return (
            "Gemini quota exhausted (HTTP 429). Online calls are skipped; "
            "use the offline pipeline or retry after the quota resets."
        )
    first_line = next(
        (line.strip() for line in str(error).splitlines() if line.strip()),
        type(error).__name__,
    )
    return first_line[:240]


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Args:
        agent: The LlmAgent instance
        runner: The InMemoryRunner instance
        user_message: Plain text message to send
        session_id: Optional session ID to continue a conversation

    Returns:
        Tuple of (response_text, session)
    """
    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response += part.text

    return final_response, session
