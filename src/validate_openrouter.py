import json
import os
import sys
from urllib import error, request

from dotenv import load_dotenv


def main() -> int:
    load_dotenv()
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key or api_key.startswith("your_"):
        print("OPENROUTER_API_KEY is missing or placeholder; update .env before running.")
        return 1

    url = "https://openrouter.ai/api/v1/models"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "http://localhost",
        "X-Title": "PyCVE Connectivity Check",
    }

    req = request.Request(url, headers=headers)
    try:
        with request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        print(f"OpenRouter HTTP error: {exc.code} {exc.reason}")
        if details:
            print(details)
        return 2
    except error.URLError as exc:
        print(f"OpenRouter connection error: {exc.reason}")
        return 3

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        print("OpenRouter response was not JSON:")
        print(body[:500])
        return 4

    model_count = len(payload.get("data", [])) if isinstance(payload, dict) else 0
    print(f"OpenRouter connectivity OK. Models available: {model_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
