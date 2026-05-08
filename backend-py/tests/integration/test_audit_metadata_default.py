"""Regression test: ``audit_log.metadata`` must satisfy the NOT NULL
constraint even when the caller of ``record_in_tx`` does not provide a
``metadata=`` argument.

History
-------
Production bug 2026-05-08: ``PATCH /api/findings/{pid}/{cve}`` returned
500 because ``record_in_tx`` was passing ``NULL`` to the ``metadata``
column, overriding the schema default ``'{}'`` and tripping the
``NOT NULL`` constraint introduced by migration 0002.
"""
from __future__ import annotations

import asyncpg
import pytest

from app.services.audit import record_in_tx


@pytest.mark.asyncio
async def test_record_in_tx_without_metadata_writes_empty_object(
    db_pool: asyncpg.Pool, clean_db
):
    async with db_pool.acquire() as conn, conn.transaction():
        row_id = await record_in_tx(
            conn,
            action="finding.status_change",
            target_type="finding",
            target_id="1:CVE-2024-TEST",
            actor_email="ui",
            actor_role="analyst",
            diff={"before": {"status": "open"}, "after": {"status": "in_review"}},
            # metadata intentionally omitted — this is the regression path
        )

    assert row_id > 0

    row = await db_pool.fetchrow(
        "SELECT metadata, diff FROM audit_log WHERE id = $1", row_id
    )
    assert row is not None
    assert row["metadata"] == "{}"
    assert row["diff"] is not None
