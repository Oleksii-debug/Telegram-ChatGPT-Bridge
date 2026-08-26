from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.verify_integration_provenance import (
    MANIFEST,
    RELEASE_OVERRIDE,
    ROOT,
    TERMINAL_DEV_B_EXACT,
    TERMINAL_DEV_B_FIRST_PARENT,
    TERMINAL_DEV_B_MERGE,
    TERMINAL_DEV_B_RETAINED,
    TERMINAL_DEV_B_SHA,
    ProvenanceError,
    _blob,
    _path_exists,
    _reject_unexpected_paths,
    _verify_overlap_matrix,
    verify_repository,
)


REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "repository-level provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


class DevAProvenanceTests(unittest.TestCase):
    @requires_repository_git
    def test_exact_candidate_provenance_is_machine_verifiable(self):
        result = verify_repository()
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["base"], "26a2df12c350f670a703b236edc3648f339b64a9")
        self.assertEqual(result["verified_predecessor_count"], 8)
        self.assertEqual(result["semantic_merge_count"], 8)
        self.assertEqual(result["dev4_override_count"], 1)
        self.assertEqual(result["dev_b_imported_path_count"], 16)
        self.assertEqual(result["dev_b_adapted_path_count"], 4)
        self.assertEqual(result["dev_b_superseded_path_count"], 2)
        self.assertEqual(result["dev_b_round2_sync_path_count"], 9)
        self.assertEqual(result["dev_b_round2_adapted_path_count"], 3)
        self.assertEqual(result["dev_b_terminal_exact_path_count"], 24)
        self.assertEqual(result["dev_b_terminal_retained_path_count"], 6)
        self.assertEqual(result["dev_c_exact_path_count"], 2)
        self.assertEqual(result["dev_c_adapted_path_count"], 2)
        self.assertEqual(result["release_to_live_path_count"], 58)
        self.assertEqual(result["pr2_pr3_overlap_count"], 7)
        self.assertEqual(result["pr2_pr5_overlap_count"], 3)
        self.assertEqual(result["rejected_dev5_overlap_count"], 7)
        self.assertFalse(result["private_values_recorded"])
        self.assertGreaterEqual(result["changed_path_count"], 100)

    @requires_repository_git
    def test_cross_pr_overlap_matrix_is_recomputed_not_trusted_as_prose(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        observed = _verify_overlap_matrix(payload)
        self.assertEqual(observed["PR2_PR3"], 7)
        self.assertEqual(observed["PR2_PR5"], 3)
        self.assertEqual(sum(observed.values()), 10)

    @requires_repository_git
    def test_rejected_dev5_overlaps_are_identical_to_dev1_authority(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        base = payload["base"]["sha"]
        rejected = payload["predecessors"]["DEV5"]["rejected_overlaps_preserve_base"]
        self.assertEqual(len(rejected), 7)
        for path in rejected:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(base, path))

    def test_ported_dev5_paths_are_disjoint_from_rejected_production_overlaps(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        dev5 = payload["predecessors"]["DEV5"]
        self.assertTrue(set(dev5["ported_paths"]).isdisjoint(dev5["rejected_overlaps_preserve_base"]))

    @requires_repository_git
    def test_dev4_write_safety_override_is_narrow_and_explicit(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(set(payload["predecessors"]["DEV4"]["dev_a_overrides"]), {"ops/write_safety.py"})
        self.assertNotEqual(
            _blob("HEAD", "ops/write_safety.py"),
            _blob(payload["predecessors"]["DEV4"]["sha"], "ops/write_safety.py"),
        )

    @requires_repository_git
    def test_dev_b_nonadapted_historical_imports_are_owned_by_exact_layers(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        dev_b = release["dev_b"]
        adapted = set(dev_b["adapted_paths"])
        round2 = set(release["dev_b_round2_sync"]["exact_blob_paths"])
        terminal = set(release["dev_b_terminal_sync"]["exact_blob_paths"])
        retained = set(release["dev_b_terminal_sync"]["retained_dev_a_adaptations"])
        for path in dev_b["imported_paths"]:
            if path in adapted or path in round2 or path in terminal or path in retained:
                continue
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(dev_b["sha"], path))

    @requires_repository_git
    def test_dev_b_round2_sync_remains_historical_and_suppression_absent(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        sync = release["dev_b_round2_sync"]
        terminal = set(release["dev_b_terminal_sync"]["exact_blob_paths"])
        self.assertEqual(sync["sha"], "6f943ee15f053acc5b4f15167c16d431023a35d1")
        self.assertEqual(sync["merge_commit"], "919d7d409564d7c21e46009e1d76cfa5d1fd602d")
        self.assertFalse(sync["strict_history_suppression_imported"])
        self.assertEqual(len(sync["exact_blob_paths"]), 9)
        for path in set(sync["exact_blob_paths"]) - terminal:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(sync["sha"], path))
        self.assertEqual(
            set(sync["retained_dev_a_adaptations"]),
            {"ops/server_manifest.py", "tests/test_devb_round2_release.py", "tests/test_server_manifest.py"},
        )
        self.assertFalse(_path_exists("HEAD", "tools/strict_history_secret_scan.py"))
        self.assertFalse(_path_exists("HEAD", "tests/test_strict_history_secret_scan.py"))

    @requires_repository_git
    def test_dev_b_terminal_sync_is_exact_with_explicit_canonical_retained_set(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        sync = release["dev_b_terminal_sync"]
        self.assertEqual(sync["sha"], TERMINAL_DEV_B_SHA)
        self.assertEqual(sync["merge_commit"], TERMINAL_DEV_B_MERGE)
        self.assertEqual(sync["first_parent"], TERMINAL_DEV_B_FIRST_PARENT)
        self.assertEqual(set(sync["exact_blob_paths"]), TERMINAL_DEV_B_EXACT)
        self.assertEqual(set(sync["retained_dev_a_adaptations"]), TERMINAL_DEV_B_RETAINED)
        self.assertFalse(sync["strict_history_suppression_imported"])
        self.assertFalse(sync["production_mutated"])
        for path in sync["exact_blob_paths"]:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(sync["sha"], path))
        for path in sync["retained_dev_a_adaptations"]:
            with self.subTest(path=path):
                self.assertNotEqual(_blob("HEAD", path), _blob(sync["sha"], path))

    @requires_repository_git
    def test_dev_c_qa_sync_is_exact_except_declared_adaptations(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        sync = release["dev_c_qa_sync"]
        self.assertEqual(sync["sha"], "5758bfdcd9ecee4011fc3caaa3c68eb46ee2af19")
        self.assertEqual(sync["merge_commit"], "df318aa089f754b7a14f624b7c27cca59758cbe8")
        self.assertEqual(sync["first_parent"], "94c6ab7e3afabd769a63b44b222bfc0bbf067f67")
        self.assertFalse(sync["production_logic_modified"])
        self.assertEqual(
            set(sync["exact_blob_paths"]),
            {"docs/DEV_C_RELEASE_TO_LIVE_QA.md", "ops/devc_release_qa.py"},
        )
        self.assertEqual(
            set(sync["adapted_paths"]),
            {"tests/test_devc_release_e2e.py", "tests/test_devc_release_qa.py"},
        )
        for path in sync["exact_blob_paths"]:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(sync["sha"], path))
        for path in sync["adapted_paths"]:
            with self.subTest(path=path):
                self.assertNotEqual(_blob("HEAD", path), _blob(sync["sha"], path))

    def test_dev_b_supersession_is_narrow_and_explicit(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        self.assertEqual(
            set(release["dev_b"]["supersedes_predecessor_paths"]),
            {"ops/hostiq_lifecycle.py", "tests/test_dev2_lifecycle.py"},
        )
        self.assertEqual(
            set(release["dev_b_terminal_sync"]["retained_dev_a_adaptations"]),
            TERMINAL_DEV_B_RETAINED,
        )

    def test_unexpected_candidate_path_is_rejected(self):
        with self.assertRaises(ProvenanceError):
            _reject_unexpected_paths({"bridge/app.py", "private/session.bin"}, {"bridge/app.py"})

    def test_manifests_contain_no_secret_value_fields_or_private_content(self):
        text = MANIFEST.read_text(encoding="utf-8") + RELEASE_OVERRIDE.read_text(encoding="utf-8")
        lowered = text.casefold()
        for forbidden in (
            "tg_api_hash",
            "tg_session_string",
            "bridge_token",
            "login_code",
            "2fa_password",
            "hostiq_cpanel_password",
            "ssh_private_key",
            "private telegram message",
        ):
            self.assertNotIn(forbidden, lowered)

    @requires_repository_git
    def test_invalid_git_path_fails_closed(self):
        with self.assertRaises(ProvenanceError):
            _blob("HEAD", "definitely/not/a/candidate/path")

    def test_provenance_files_live_inside_repository(self):
        self.assertEqual(ROOT, Path(__file__).resolve().parents[1])
        self.assertTrue(MANIFEST.is_file())
        self.assertTrue(RELEASE_OVERRIDE.is_file())


if __name__ == "__main__":
    unittest.main()


# FINALWAVE-33: machine-enforced provenance for post-baseline swarm integrations.
# This section intentionally consumes the existing canonical manifest rather than
# adding a second prose ledger that could diverge from the Git object graph.
from pathlib import PurePosixPath
from unittest import mock
from tools.verify_integration_provenance import _assert_ancestor, _git, _parents

CANONICAL_PR9_BASE = "26a2df12c350f670a703b236edc3648f339b64a9"
CANONICAL_PR9_ANCHOR = "84691967e5363bc4b88dfae97371d7bf329c105d"
CANONICAL_PR9_MERGE = "0516bf242bb7e4551435e99a516a20d8785590b1"
EXPECTED_SWARM_INTEGRATIONS = {
    "DEV03_READ_HARDENING",
    "DEV04_MEDIA_STORAGE",
    "DEV07_AUDIT_SINK",
    "DEV08_DEPLOYMENT_RECOVERY_ORACLE",
}


def _exact_paths(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ProvenanceError(f"{label}: explicit path list required")
    if value != sorted(set(value)):
        raise ProvenanceError(f"{label}: paths must be unique and sorted")
    result: list[str] = []
    for raw in value:
        if not isinstance(raw, str) or not raw:
            raise ProvenanceError(f"{label}: invalid path")
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts or raw.endswith("/"):
            raise ProvenanceError(f"{label}: unsafe/non-exact path")
        if any(ch in raw for ch in "*?[]{}"):
            raise ProvenanceError(f"{label}: wildcard/pattern path forbidden")
        result.append(raw)
    return tuple(result)


def _require_merge_parent_order(merge_commit: str, first_parent: str, source_sha: str) -> None:
    if _parents(merge_commit) != (first_parent, source_sha):
        raise ProvenanceError("semantic merge parent order/source identity mismatch")


def _require_exact_blob(candidate: str, source_sha: str, path: str) -> None:
    if _blob(candidate, path) != _blob(source_sha, path):
        raise ProvenanceError(f"silent specialist-path mutation: {path}")


def _require_adaptation_blob(candidate: str, source_sha: str, adaptation_commit: str, path: str) -> None:
    source_blob = _blob(source_sha, path)
    adapted_blob = _blob(adaptation_commit, path)
    if source_blob == adapted_blob:
        raise ProvenanceError(f"declared adaptation/supersession has no blob delta: {path}")
    if _blob(candidate, path) != adapted_blob:
        raise ProvenanceError(f"unregistered post-adaptation mutation: {path}")


class FinalwaveSwarmProvenanceGuardTests(unittest.TestCase):
    def _candidate_from_pr_merge(self) -> tuple[str, str, str]:
        head = _git("rev-parse", "HEAD")
        parents = _parents(head)
        if len(parents) != 2:
            self.fail("provenance CI must execute on a two-parent PR merge ref")
        pr_base, candidate = parents
        self.assertEqual(pr_base, _git("merge-base", pr_base, candidate))
        self.assertEqual(_git("rev-parse", f"{head}^{{tree}}"), _git("rev-parse", f"{candidate}^{{tree}}"))
        return pr_base, candidate, head

    @requires_repository_git
    def test_fixed_canonical_anchor_binds_base_candidate_and_pr_merge(self):
        self.assertEqual((CANONICAL_PR9_BASE, CANONICAL_PR9_ANCHOR), _parents(CANONICAL_PR9_MERGE))
        self.assertEqual(
            _git("rev-parse", f"{CANONICAL_PR9_MERGE}^{{tree}}"),
            _git("rev-parse", f"{CANONICAL_PR9_ANCHOR}^{{tree}}"),
        )
        pr_base, candidate, pr_merge = self._candidate_from_pr_merge()
        self.assertEqual(pr_base, _parents(pr_merge)[0])
        self.assertEqual(candidate, _parents(pr_merge)[1])
        _assert_ancestor(CANONICAL_PR9_ANCHOR, candidate)

    @requires_repository_git
    def test_all_swarm_integrations_have_exact_ordered_ancestry_blobs_and_exclusions(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        integrations = payload.get("swarm_integrations")
        self.assertIsInstance(integrations, dict)
        self.assertEqual(EXPECTED_SWARM_INTEGRATIONS, set(integrations))
        _, candidate, _ = self._candidate_from_pr_merge()
        owned: dict[str, str] = {}
        for owner, record in sorted(integrations.items()):
            with self.subTest(owner=owner):
                source = record["source_sha"]
                merge_commit = record["merge_commit"]
                first_parent = record["first_parent"]
                _require_merge_parent_order(merge_commit, first_parent, source)
                _assert_ancestor(merge_commit, candidate)
                exact = _exact_paths(record["exact_blob_paths"], f"{owner}.exact")
                excluded = _exact_paths(record.get("excluded_specialist_paths", []), f"{owner}.excluded", allow_empty=True)
                self.assertTrue(set(exact).isdisjoint(excluded))
                for path in exact:
                    self.assertNotIn(path, owned, f"specialist path has ambiguous owner: {path}")
                    owned[path] = owner
                    _require_exact_blob(candidate, source, path)
                for path in excluded:
                    self.assertTrue(_path_exists(source, path), f"excluded source path missing: {owner}:{path}")
                    self.assertFalse(_path_exists(candidate, path), f"excluded specialist path leaked into candidate: {owner}:{path}")

        dev08 = integrations["DEV08_DEPLOYMENT_RECOVERY_ORACLE"]
        runtime_source = dev08["authoritative_runtime_source_sha"]
        runtime_paths = _exact_paths(dev08["authoritative_runtime_paths"], "DEV08.authoritative_runtime")
        for path in runtime_paths:
            self.assertNotIn(path, owned, f"path has two specialist owners: {path}")
            owned[path] = "DEV08_AUTHORITATIVE_RUNTIME"
            _require_exact_blob(candidate, runtime_source, path)

        # dev_a_paths remains a compatibility candidate-diff allowlist. Specialist
        # ownership for every overlap above is resolved by the exact records, so a
        # generic allowlist entry cannot be the sole provenance authority.
        generic_allowlist = set(payload["dev_a_paths"])
        overlaps = generic_allowlist & set(owned)
        self.assertTrue(overlaps)
        self.assertEqual(overlaps, {path for path in generic_allowlist if path in owned})

    @requires_repository_git
    def test_adapted_and_superseded_paths_are_pinned_to_source_and_canonical_blob(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        _, candidate, _ = self._candidate_from_pr_merge()
        _assert_ancestor(CANONICAL_PR9_ANCHOR, candidate)

        records: list[tuple[str, str, str]] = []
        for lane in ("DEV3", "DEV4"):
            row = payload["predecessors"][lane]
            records.extend((row["sha"], path, f"{lane}.dev_a_override") for path in row.get("dev_a_overrides", []))
        dev5 = payload["predecessors"]["DEV5"]
        records.extend((dev5["sha"], path, "DEV5.dev_a_override") for path in dev5.get("dev_a_overrides", []))

        dev_b = release["dev_b"]
        records.extend((dev_b["sha"], path, "DEV_B.adapted") for path in dev_b["adapted_paths"])
        records.extend((dev_b["sha"], path, "DEV_B.superseded") for path in dev_b["supersedes_predecessor_paths"])
        terminal = release["dev_b_terminal_sync"]
        records.extend((terminal["sha"], path, "DEV_B.terminal_retained") for path in terminal["retained_dev_a_adaptations"])
        dev_c = release["dev_c_qa_sync"]
        records.extend((dev_c["sha"], path, "DEV_C.adapted") for path in dev_c["adapted_paths"])

        self.assertGreaterEqual(len(records), 20)
        for source, path, owner in records:
            with self.subTest(owner=owner, path=path):
                _exact_paths([path], f"{owner}.path")
                _assert_ancestor(source, CANONICAL_PR9_ANCHOR)
                _require_adaptation_blob(candidate, source, CANONICAL_PR9_ANCHOR, path)

    def test_parent_order_spoof_is_rejected(self):
        with mock.patch(__name__ + "._parents", return_value=("b" * 40, "a" * 40)):
            with self.assertRaises(ProvenanceError):
                _require_merge_parent_order("c" * 40, "a" * 40, "b" * 40)

    def test_silent_post_adaptation_mutation_is_rejected(self):
        values = {
            ("source", "p.py"): "1" * 40,
            ("adapt", "p.py"): "2" * 40,
            ("candidate", "p.py"): "3" * 40,
        }
        with mock.patch(__name__ + "._blob", side_effect=lambda ref, path: values[(ref, path)]):
            with self.assertRaises(ProvenanceError):
                _require_adaptation_blob("candidate", "source", "adapt", "p.py")

    def test_wildcard_and_prefix_paths_fail_closed(self):
        for path in ("bridge/*", "tests/", "../escape", "/absolute", "ops/[ab].py"):
            with self.subTest(path=path):
                with self.assertRaises(ProvenanceError):
                    _exact_paths([path], "adversarial")
