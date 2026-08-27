from __future__ import annotations

import sqlite3
import unittest
from unittest import mock

from bridge.storage import _configure_sqlite_connection, _sqlite_lock_contention


class _Result:
    def __init__(self, value: str) -> None:
        self.value = value

    def fetchone(self):
        return (self.value,)


class _FakeConnection:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls: list[str] = []

    def execute(self, sql: str):
        self.calls.append(sql)
        if sql.startswith("PRAGMA busy_timeout="):
            return _Result("ok")
        if sql == "PRAGMA journal_mode=WAL":
            action = self.actions.pop(0)
            if isinstance(action, BaseException):
                raise action
            return _Result(str(action))
        if sql == "PRAGMA synchronous=FULL":
            return _Result("ok")
        raise AssertionError(sql)


def _operational_error(code: int, message: str = "synthetic") -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError(message)
    exc.sqlite_errorcode = code
    return exc


class SQLiteWalBootstrapTests(unittest.TestCase):
    def test_busy_and_locked_codes_are_classified_by_numeric_code(self) -> None:
        self.assertTrue(_sqlite_lock_contention(_operational_error(sqlite3.SQLITE_BUSY)))
        self.assertTrue(_sqlite_lock_contention(_operational_error(sqlite3.SQLITE_LOCKED)))
        self.assertFalse(_sqlite_lock_contention(_operational_error(sqlite3.SQLITE_ERROR, "database is locked")))
        self.assertFalse(_sqlite_lock_contention(sqlite3.OperationalError("database is locked")))

    def test_transient_busy_retries_then_enables_wal(self) -> None:
        connection = _FakeConnection([
            _operational_error(sqlite3.SQLITE_BUSY),
            _operational_error(sqlite3.SQLITE_LOCKED),
            "wal",
        ])
        with mock.patch("bridge.storage.time.sleep") as sleep:
            _configure_sqlite_connection(connection)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(connection.calls[-1], "PRAGMA synchronous=FULL")

    def test_non_contention_operational_error_fails_without_retry(self) -> None:
        failure = _operational_error(sqlite3.SQLITE_ERROR, "database is locked")
        connection = _FakeConnection([failure])
        with mock.patch("bridge.storage.time.sleep") as sleep:
            with self.assertRaises(sqlite3.OperationalError) as caught:
                _configure_sqlite_connection(connection)
        self.assertIs(caught.exception, failure)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 1)
        sleep.assert_not_called()

    def test_unexpected_journal_mode_fails_closed(self) -> None:
        connection = _FakeConnection(["delete"])
        with self.assertRaises(sqlite3.OperationalError):
            _configure_sqlite_connection(connection)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 1)
        self.assertNotIn("PRAGMA synchronous=FULL", connection.calls)

    def test_retry_budget_exhaustion_propagates_lock_error(self) -> None:
        failure = _operational_error(sqlite3.SQLITE_BUSY)
        connection = _FakeConnection([failure])
        with mock.patch("bridge.storage.time.monotonic", side_effect=[10.0, 18.0]):
            with mock.patch("bridge.storage.time.sleep") as sleep:
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    _configure_sqlite_connection(connection)
        self.assertIs(caught.exception, failure)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
