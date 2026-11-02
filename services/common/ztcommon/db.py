"""Async PostgreSQL pool authenticated by the service's mTLS certificate."""
from __future__ import annotations

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from . import config

_pool: AsyncConnectionPool | None = None


async def pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        _pool = AsyncConnectionPool(
            config.pg_conninfo(),
            min_size=1,
            max_size=8,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=False,
        )
        await _pool.open(wait=True, timeout=30)
    return _pool


async def close() -> None:
    if _pool is not None:
        await _pool.close()
