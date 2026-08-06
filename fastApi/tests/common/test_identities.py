"""
Identidades compartidas para tests FastAPI de Praesidium.
Shared identities for Praesidium FastAPI tests.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class TestIdentity:
    """Identidad de test esperada. / Expected test identity."""
    username: str
    password: str
    role: str
    language: str = "english"
    description: str = ""

# ES: Viewer de pruebas: puede consultar, no crear/modificar/eliminar.
# EN: Test viewer: can read/query, cannot create/update/delete.
TEST_VIEWER = TestIdentity("testuser", "1234", "viewer", "espanol", "read-only viewer test user")

# ES: Admin de pruebas: puede consultar, crear, modificar y eliminar.
# EN: Test admin: can read/query, create, update, and delete.
TEST_ADMIN = TestIdentity("testuser2", "1234", "admin", "english", "full CRUD admin test user")

# ES: Identidades usadas por los orquestadores.
# EN: Identities used by orchestrators.
TEST_IDENTITIES = (TEST_VIEWER, TEST_ADMIN)
