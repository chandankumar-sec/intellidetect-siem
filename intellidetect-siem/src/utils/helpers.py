"""Helper utility functions."""
import json
from datetime import datetime
from typing import Any, Dict, List

def generate_id(prefix: str = '') -> str:
    """Generate a unique ID with optional prefix."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    import random
    suffix = ''.join([str(random.randint(0, 9)) for _ in range(4)])
    return f"{prefix}{timestamp}{suffix}" if prefix else f"{timestamp}{suffix}"

def to_json(obj: Any) -> str:
    """Convert object to JSON string."""
    return json.dumps(obj, default=str, indent=2)

def from_json(json_str: str) -> Any:
    """Parse JSON string to object."""
    return json.loads(json_str)

def get_timestamp() -> str:
    """Get current timestamp as ISO format string."""
    return datetime.now().isoformat()
