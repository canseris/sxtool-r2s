"""Types and data structures for the exploit tool."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class RemoteFile:
    """Represents a remote file or directory."""
    name: str
    is_dir: bool
    size: int
    
    @classmethod
    def from_json(cls, data: dict):
        """Create RemoteFile from JSON dict with short keys."""
        return cls(
            name=data.get('n', ''),
            is_dir=data.get('d', False),
            size=data.get('s', -1)
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'n': self.name,
            'd': self.is_dir,
            's': self.size
        }


@dataclass
class ExploitResult:
    """Result of an exploit operation."""
    success: bool
    result: str = ""
    error: Optional[str] = None
    status_code: Optional[int] = None

