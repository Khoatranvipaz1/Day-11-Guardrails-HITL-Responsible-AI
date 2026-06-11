"""
Lab 11 — Configuration & API Key Setup
"""
import os

from dotenv import load_dotenv


def setup_api_key():
    """Load Google API configuration from .env, environment, or a prompt."""
    load_dotenv()
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if not api_key or api_key == "replace_with_your_google_api_key":
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
