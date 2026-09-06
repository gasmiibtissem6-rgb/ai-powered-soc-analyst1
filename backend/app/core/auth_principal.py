from dataclasses import dataclass
from typing import List, Optional


@dataclass
class AuthPrincipal:
    subject: str
    roles: List[str]
    source: str
    email: Optional[str] = None
    full_name: Optional[str] = None

    def has_role(
        self,
        role: str,
    ) -> bool:
        return role in self.roles