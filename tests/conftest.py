"""Fixtures compartidas.

El motor de defensa (``lab_origin.defense``) es un singleton de proceso y lee su
config del entorno. Para que un test de abuso no "contamine" al resto (ni rompa el
E2E de la Etapa 1, que mide el ataque SIN defensas), este autouse lo deja apagado
antes de cada test. Cada test de la Etapa 2 enciende lo que necesita y resetea.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _defense_off_by_default(monkeypatch):
    from lab_origin import defense

    monkeypatch.delenv("SVD_DEFENSE", raising=False)
    defense.reset_engine(defense.DefenseConfig(enabled=False))
    yield
    defense.reset_engine(defense.DefenseConfig(enabled=False))
