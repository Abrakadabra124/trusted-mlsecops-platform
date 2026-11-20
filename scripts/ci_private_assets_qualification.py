"""Offline qualification of the private release lifecycle, including interrupted mutations."""

import unittest
from copy import deepcopy
from unittest.mock import patch

from mlsecops.contracts import Rejected, canonical, digest
from scripts import ci_private_assets as store

ROOT = "repos/Abrakadabra124/trusted-mlsecops-ci-private"
EXPECTED = dict(
    repository="Abrakadabra124/trusted-mlsecops-platform",
    run_id=123,
    run_attempt=1,
    source_revision="e" * 40,
    producer_job="producer",
)
HEAD = "a" * 40
TAG = "ci-candidate-123-1"
REF = "refs/tags/" + TAG
PACKETS = {
    name: b"MLSCIT\x01" + bytes(range(29)) + name.encode()
    for name in ("candidate-shared", "candidate-serving", "upstream-serving", "validation-serving")
}
CONTROL = b"MLSCONTROL\x01" + bytes(range(30))


class StoreAPI:
    """Stateful GitHub fixture. No sockets or credentials. All paths must match exactly."""

    def __init__(self):
        self.repo = dict(
            id=1465012664,
            full_name=ROOT[6:],
            private=True,
            visibility="private",
            fork=False,
            owner={"login": "Abrakadabra124"},
            default_branch="qualify/store",
        )
        self.branch = self.ref("refs/heads/qualify/store", HEAD)
        self.tag = self.release = None
        self.assets = {}
        self.contents = {}
        self.mutations = []
        self.downloads = []
        self.sibling = []
        self.next_id = 100
        self.hook = lambda method, path, result: result

    @staticmethod
    def ref(ref, sha):
        return {"ref": ref, "object": {"type": "commit", "sha": sha}}

    def json(self, method, path, *, body=None, absent=False):
        path = path.removeprefix(ROOT)
        if method != "GET":
            self.mutations.append((method, path))
        if method == "POST" and path == "/git/refs":
            if self.tag or body != {"ref": REF, "sha": HEAD}:
                raise Rejected("existing or unsupported ref")
            self.tag = self.ref(REF, HEAD)
            value = self.tag
        elif method == "POST" and path == "/releases":
            if self.release or self.tag is None:
                raise Rejected("ambiguous")
            self.release = {
                k: body[k]
                for k in ("tag_name", "target_commitish", "name", "draft", "prerelease", "body")
            }
            self.release.update(id=71, immutable=False)
            value = self.release | {"assets": []}
        elif method == "DELETE":
            if path in ["/releases/assets/" + str(i) for i in self.assets]:
                i = int(path.split("/")[-1])
                del self.assets[i], self.contents[i]
            elif path == "/releases/71" and self.release and not self.assets:
                self.release = None
            elif path == "/git/refs/tags/" + TAG and self.tag and self.release is None:
                self.tag = None
            else:
                raise AssertionError(("unsafe deletion", path))
            value = {}
        elif method == "GET":
            release = self.release and self.release | {"assets": list(self.assets.values())}
            routes = {
                "": self.repo,
                "/git/ref/heads/qualify/store": self.branch,
                "/git/ref/tags/" + TAG: self.tag,
                "/releases?per_page=20": (self.sibling + ([release] if release else []))[:20],
                "/releases?per_page=100": (self.sibling + ([release] if release else []))[:100],
                "/releases/tags/" + TAG: release,
                "/releases/71": release,
                "/releases/71/assets?per_page=6": list(self.assets.values()) if release else None,
            }
            if path.startswith("/releases/assets/"):
                value = self.assets.get(int(path.split("/")[-1]))
            else:
                value = routes[path]
            if value is None and not absent:
                raise Rejected("not found")
        else:
            raise AssertionError((method, path))
        return self.hook(method, path, deepcopy(value))

    def upload(self, path, name, content):
        assert path == ROOT + "/releases/71/assets"
        assert name not in [a["name"] for a in self.assets.values()]
        i = self.next_id
        self.next_id += 1
        self.mutations.append(("UPLOAD", name))
        self.assets[i] = dict(
            id=i, name=name, size=len(content), state="uploaded", digest="sha256:" + digest(content)
        )
        self.contents[i] = content
        return self.hook("UPLOAD", name, self.assets[i].copy())

    def download(self, path, limit):
        i = int(path.removeprefix(ROOT + "/releases/assets/"))
        self.downloads.append((i, limit))
        raw = self.contents[i]
        assert len(raw) <= limit
        return self.hook("DOWNLOAD", path, raw)


class PrivateAssetsTests(unittest.TestCase):
    def setUp(self):
        self.api = StoreAPI()
        self.clock = self.enterContext(patch("time.time", return_value=10000))
        self.signed = None
        self.copies = PACKETS | {"producer-control": CONTROL}
        self.journal = []

    def seal(self, receipt):
        self.signed = deepcopy(receipt)
        return CONTROL

    def publish(self):
        return store.publish(self.api, EXPECTED, PACKETS, self.seal, checkpoint=self.journal.append)

    def authorize(self, receipt):
        return dict(terminal=True, primary=True, receipt_sha256=digest(canonical(receipt)))

    def clean(self, receipt, **options):
        store.cleanup(
            self.api,
            EXPECTED,
            receipt,
            **({"authorize": self.authorize, "retained_copy": self.copies.__getitem__} | options),
        )

    def test_roundtrip_and_terminal_cleanup(self):
        receipt = self.publish()
        self.assertEqual(set(self.signed["assets"]), PACKETS.keys())
        self.assertEqual(set(receipt["assets"]), self.copies.keys())
        self.assertEqual(receipt["private_head"], HEAD)
        self.assertEqual(receipt["expected"], EXPECTED)
        self.assertEqual(receipt["tag"], TAG)
        self.assertEqual(self.journal[-1], receipt)
        self.assertEqual(store.fetch_control(self.api, EXPECTED), CONTROL)
        for name, packet in PACKETS.items():
            self.assertEqual(store.fetch(self.api, EXPECTED, self.signed, name), packet)
            self.assertEqual(
                self.api.downloads[-1], (self.signed["assets"][name]["id"], len(packet))
            )
        self.clean(receipt)
        self.assertIsNone(self.api.release)
        self.assertIsNone(self.api.tag)
        self.assertFalse(self.api.assets)

    def test_public_fork_and_identity_drift_refuse_before_mutation(self):
        for field, bad in {
            "id": 1465012665,
            "full_name": ROOT.upper(),
            "private": False,
            "visibility": "public",
            "fork": True,
            "owner": {"login": "abrakadabra124"},
            "default_branch": "../other",
        }.items():
            with self.subTest(field=field):
                self.api = StoreAPI()
                self.api.repo[field] = bad
                with self.assertRaises(Rejected):
                    self.publish()
                self.assertEqual(self.api.mutations, [])

    def test_publish_once_even_when_data_are_identical(self):
        self.publish()
        before = list(self.api.mutations)
        with self.assertRaises(Rejected):
            self.publish()
        self.assertEqual(self.api.mutations, before)

    def test_stale_tag_or_draft_owned_by_someone_else(self):
        self.api.tag = self.api.ref(REF, HEAD)
        with self.assertRaises(Rejected):
            self.publish()
        self.api.tag = None
        self.api.sibling = [{"tag_name": TAG, "id": 90, "draft": True}]
        with self.assertRaises(Rejected):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_extra_foreign_asset_stops_all_deletes(self):
        receipt = self.publish()
        self.api.assets[202] = self.api.assets[100] | {"id": 202, "name": "foreign.bin"}
        before = list(self.api.mutations)
        with self.assertRaises(Rejected):
            self.clean(receipt)
        self.assertEqual(self.api.mutations, before)

    def test_primary_needs_independent_matching_readback(self):
        receipt = self.publish()
        before = list(self.api.mutations)
        for args in (
            dict(authorize=None),
            dict(authorize=lambda r: True),
            dict(authorize=lambda r: self.authorize(r) | {"terminal": False}),
            dict(authorize=lambda r: self.authorize(r) | {"receipt_sha256": "a" * 64}),
            dict(retained_copy=None),
            dict(retained_copy=lambda name: b"other"),
        ):
            with self.subTest(args=list(args)), self.assertRaises(Rejected):
                self.clean(receipt, **args)
        self.assertEqual(self.api.mutations, before)

    def test_signed_receipt_normalizer_requires_all_four_data_rows_and_unexpired_window(self):
        receipt = self.publish()
        normalized = store.producer_receipt(self.signed, EXPECTED)
        self.assertEqual(normalized, self.signed)
        normalized["assets"].clear()
        self.assertEqual(set(self.signed["assets"]), PACKETS.keys())
        for wrong in (
            receipt,
            self.journal[2],
            self.signed | {"schema_version": True},
            self.signed | {"unknown": 1},
            self.signed | {"release_id": None},
            self.signed | {"tag": TAG + "x"},
            self.signed | {"expires_at": 10001},
        ):
            with self.subTest(keys=tuple(wrong)), self.assertRaises(Rejected):
                store.producer_receipt(wrong, EXPECTED)
        self.clock.return_value = receipt["expires_at"]
        with self.assertRaises(Rejected):
            store.producer_receipt(self.signed, EXPECTED)

    def test_foreign_listing_during_signing_refuses_before_control_upload(self):
        def seal_and_insert(receipt):
            self.api.assets[202] = self.api.assets[100] | {"id": 202, "name": "other.bin"}
            return self.seal(receipt)

        with self.assertRaises(Rejected):
            store.publish(self.api, EXPECTED, PACKETS, seal_and_insert)
        self.assertNotIn(("UPLOAD", "producer-control.bin"), self.api.mutations)

    def test_each_acknowledged_partial_publication_can_be_cleaned_using_its_checkpoint(self):
        for stop in range(1, 8):
            self.api = StoreAPI()
            journal = []

            def stop_after(receipt):
                journal.append(receipt)
                if len(journal) == stop:
                    raise OSError("cancelled")

            with self.subTest(stop=stop), self.assertRaises(OSError):
                store.publish(self.api, EXPECTED, PACKETS, self.seal, checkpoint=stop_after)
            self.assertFalse(any(method == "DELETE" for method, _ in self.api.mutations))
            self.clean(journal[-1])
            self.assertIsNone(self.api.tag)
            self.assertIsNone(self.api.release)
            self.assertFalse(self.api.assets)

    def test_cleanup_resumes_after_loss_of_an_acknowledged_delete_response(self):
        for stop in range(1, 8):
            self.api = StoreAPI()
            receipt = self.publish()
            count = 0

            def stop_after(method, path, result):
                nonlocal count
                if method == "DELETE":
                    count += 1
                    if count == stop:
                        raise OSError("connection lost after DELETE")
                return result

            self.api.hook = stop_after
            with self.subTest(stop=stop), self.assertRaises(OSError):
                self.clean(receipt)
            self.api.hook = lambda m, p, r: r
            self.clean(receipt)
            deleted = [p for m, p in self.api.mutations if m == "DELETE"]
            self.assertEqual(len(deleted), 7)
            self.assertEqual(len(set(deleted)), 7)

    def test_unknown_upload_outcome_preserves_ambiguous_listing(self):
        def disconnect(method, path, result):
            if method == "UPLOAD":
                raise OSError("server accepted; metadata unavailable")
            return result

        self.api.hook = disconnect
        with self.assertRaises(OSError):
            self.publish()
        self.api.hook = lambda m, p, r: r
        with self.assertRaises(Rejected):
            self.clean(self.journal[-1])
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_window_refuses_future_expired_and_expiry_during_download(self):
        receipt = self.publish()
        for when in (9999, 11800):
            self.clock.return_value = when
            for action in (
                lambda: store.fetch_control(self.api, EXPECTED),
                lambda: store.fetch(self.api, EXPECTED, self.signed, "candidate-shared"),
            ):
                before = len(self.api.downloads)
                with self.assertRaises(Rejected):
                    action()
                self.assertEqual(len(self.api.downloads), before)

        def expire(method, path, result):
            if method == "DOWNLOAD":
                self.clock.return_value = 11800
            return result

        self.api.hook = expire
        for action in (
            lambda: store.fetch_control(self.api, EXPECTED),
            lambda: store.fetch(self.api, EXPECTED, receipt, "candidate-shared"),
        ):
            self.clock.return_value = 10000
            with self.assertRaises(Rejected):
                action()
        self.clean(
            receipt, authorize=lambda r: self.authorize(r) | {"primary": False}, retained_copy=None
        )

    def test_malformed_wire_rejected_before_tag_including_non_ciphertext_control(self):
        for raw in (
            b"cleartext",
            b"MLSCIT\x01" + bytes(27),
            bytearray(PACKETS["candidate-shared"]),
        ):
            with self.assertRaises(Rejected):
                store.publish(self.api, EXPECTED, PACKETS | {"candidate-shared": raw}, self.seal)
        for packets in (
            PACKETS | {"foreign": b"x"},
            {k: v for k, v in PACKETS.items() if k != "upstream-serving"},
        ):
            with self.assertRaises(Rejected):
                store.publish(self.api, EXPECTED, packets, self.seal)
        self.assertEqual(self.api.mutations, [])
        for invalid in (
            bytes(100),
            b"MLSCONTROL\x01" + bytes(27),
            b"MLSCONTROL\x01" + bytes(65536),
        ):
            self.api = StoreAPI()
            with self.assertRaises(Rejected):
                store.publish(self.api, EXPECTED, PACKETS, lambda r: invalid)
            self.assertNotIn(("UPLOAD", "producer-control.bin"), self.api.mutations)

    def test_expected_context_is_independent_and_type_strict(self):
        receipt = self.publish()
        for field, wrong in (
            ("repository", ROOT[6:]),
            ("run_id", True),
            ("run_attempt", 0),
            ("source_revision", "A" * 40),
            ("source_revision", "f" * 40),
            ("producer_job", "cleanup"),
            ("run_id", 124),
        ):
            owner = EXPECTED | {field: wrong}
            with self.subTest(field=field, wrong=wrong):
                with self.assertRaises(Rejected):
                    store.fetch(self.api, owner, self.signed, "candidate-shared")
                with self.assertRaises(Rejected):
                    store.cleanup(
                        self.api,
                        owner,
                        receipt,
                        authorize=self.authorize,
                        retained_copy=self.copies.__getitem__,
                    )
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_listing_above_bound_or_without_shape_refuses_before_tag_or_deletes(self):
        for rows in ([{"tag_name": "other"}] * 20, [None], {}):
            self.api.hook = lambda m, p, r: rows if p.endswith("?per_page=20") else r
            with self.assertRaises(Rejected):
                self.publish()
        self.assertEqual(self.api.mutations, [])
        self.api.hook = lambda m, p, r: r
        receipt = self.publish()
        first = self.api.assets[100]
        for rows in (
            None,
            [first, first],
            [first, first | {"name": "candidate-serving.bin"}],
            [None],
            [first | {"name": "unexpected.bin"}],
            [first | {"digest": None}],
            [first | {"id": True}],
            [first | {"digest": "sha256:" + "Z" * 64}],
            [],
        ):
            self.api.hook = lambda m, p, r: rows if p.endswith("?per_page=6") else r
            with self.assertRaises(Rejected):
                self.clean(receipt)
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_drifted_tag_release_id_marker_or_direct_asset_rejects_access_and_cleanup(self):
        receipt = self.publish()
        for path, delta in (
            ("/git/ref/tags/" + TAG, {"object": {"type": "tag", "sha": HEAD}}),
            ("/git/ref/tags/" + TAG, {"object": {"type": "commit", "sha": "f" * 40}}),
            ("/releases/tags/" + TAG, {"id": 72}),
            ("/releases/71", {"target_commitish": "main"}),
            ("/releases/71", {"immutable": True}),
            ("/releases/71", {"body": "other"}),
            ("/releases/71", {"draft": 0}),
            ("/releases/assets/100", {"name": "candidate-serving.bin"}),
            ("/releases/assets/100", {"size": 999}),
        ):
            self.api.hook = lambda m, p, r: r | delta if p == path else r
            with self.subTest(path=path), self.assertRaises(Rejected):
                store.fetch(self.api, EXPECTED, self.signed, "candidate-shared")
            with self.assertRaises(Rejected):
                self.clean(receipt)
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_content_replacement_and_retained_last_file_corruption(self):
        receipt = self.publish()
        self.api.hook = lambda m, p, r: r[:-1] + b"X" if m == "DOWNLOAD" else r
        with self.assertRaises(Rejected):
            store.fetch(self.api, EXPECTED, self.signed, "candidate-shared")
        self.api.hook = lambda m, p, r: r
        with self.assertRaises(Rejected):
            self.clean(
                receipt,
                retained_copy=lambda k: (
                    CONTROL[:-1] + b"Y" if k == "producer-control" else PACKETS[k]
                ),
            )
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_no_cleanup_success_on_failed_final_positive_readback(self):
        receipt = self.publish()

        def lose_access(method, path, result):
            if path == "/git/ref/heads/qualify/store":
                raise Rejected("no-access")
            return result

        self.api.hook = lose_access
        with self.assertRaises(Rejected):
            self.clean(receipt)

    def test_refuse_publication_if_own_release_would_exhaust_listing_capacity(self):
        self.api.sibling = [dict(id=i + 5, tag_name="unrelated-" + str(i)) for i in range(19)]
        with self.assertRaises(Rejected):
            self.publish()
        self.assertEqual(self.api.mutations, [])

    def test_draft_appearing_during_reservation_prevents_release_post(self):
        def checkpoint(r):
            self.api.sibling = [{"tag_name": TAG, "id": 80, "draft": True}]

        with self.assertRaises(Rejected):
            store.publish(self.api, EXPECTED, PACKETS, self.seal, checkpoint=checkpoint)
        self.assertEqual(self.api.mutations, [("POST", "/git/refs")])

    def test_other_runs_releases_remain_available_after_cleanup(self):
        siblings = [
            {"id": 92, "tag_name": "ci-candidate-123-2"},
            {"id": 93, "tag_name": "ordinary-release"},
        ]
        self.api.sibling = deepcopy(siblings)
        receipt = self.publish()
        self.clean(receipt)
        self.assertEqual(self.api.sibling, siblings)

    def test_loss_of_privacy_after_first_upload_stops_readback_and_subsequent_writes(self):
        def reveal(method, path, result):
            if method == "UPLOAD":
                self.api.repo["visibility"] = "public"
            return result

        self.api.hook = reveal
        with self.assertRaises(Rejected):
            self.publish()
        self.assertEqual(self.api.downloads, [])
        self.assertEqual([m for m, p in self.api.mutations], ["POST", "POST", "UPLOAD"])

    def test_asset_at_another_id_or_shuffled_metadata_cannot_replace_signed_row(self):
        receipt = self.publish()
        pin = receipt["assets"]["candidate-shared"]
        self.api.assets[850] = self.api.assets.pop(pin["id"]) | {"id": 850}
        self.api.contents[850] = self.api.contents.pop(pin["id"])
        count = len(self.api.downloads)
        with self.assertRaises(Rejected):
            store.fetch(self.api, EXPECTED, self.signed, "candidate-shared")
        with self.assertRaises(Rejected):
            self.clean(receipt)
        self.assertEqual(len(self.api.downloads), count)
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_tampered_late_asset_id_or_disagreeing_listing_blocks_first_delete(self):
        receipt = self.publish()
        path = "/releases/assets/" + str(receipt["assets"]["producer-control"]["id"])
        self.api.hook = lambda m, p, r: r | {"id": 500} if p == path else r
        with self.assertRaises(Rejected):
            self.clean(receipt)
        self.api.hook = lambda m, p, r: r | {"assets": []} if p == "/releases/71" else r
        with self.assertRaises(Rejected):
            self.clean(receipt)
        self.assertFalse(any(m == "DELETE" for m, p in self.api.mutations))

    def test_private_head_is_pinned_even_if_default_branch_advances_after_publication(self):
        receipt = self.publish()
        self.api.branch = self.api.ref("refs/heads/qualify/store", "f" * 40)
        self.assertEqual(store.fetch_control(self.api, EXPECTED), CONTROL)
        self.assertEqual(
            store.fetch(self.api, EXPECTED, self.signed, "candidate-shared"),
            PACKETS["candidate-shared"],
        )
        self.clean(receipt)
        self.assertEqual(self.api.branch["object"]["sha"], "f" * 40)

    def test_different_context_cannot_bootstrap_opaque_control(self):
        self.publish()
        before = list(self.api.downloads)
        with self.assertRaises(Rejected):
            store.fetch_control(self.api, EXPECTED | {"source_revision": "b" * 40})
        self.assertEqual(self.api.downloads, before)

    def test_bad_post_or_upload_response_and_truncated_readback_stop_publication(self):
        for method, bad in (
            ("UPLOAD", lambda r: r | {"digest": "sha256:" + "c" * 64}),
            ("UPLOAD", lambda r: r | {"size": r["size"] + 1}),
            ("DOWNLOAD", lambda r: r[:-1]),
        ):
            self.api = StoreAPI()
            self.api.hook = lambda m, p, r: bad(r) if m == method else r
            with self.assertRaises(Rejected):
                self.publish()
            self.assertEqual([m for m, p in self.api.mutations], ["POST", "POST", "UPLOAD"])

    def test_ref_namespace_collision_between_absence_and_create_never_adopts(self):
        def racer(method, path, result):
            if method == "GET" and path == "/git/ref/tags/" + TAG:
                self.api.tag = self.api.ref(REF, "d" * 40)
            return result

        self.api.hook = racer
        with self.assertRaises(Rejected):
            self.publish()
        self.assertIsNone(self.api.release)
        self.assertEqual(self.journal, [])
        self.assertEqual(self.api.tag["object"]["sha"], "d" * 40)

    def test_out_of_range_receipt_never_reaches_terminal_authority(self):
        receipt = self.publish() | {"issued_at": 2**53 - 1, "expires_at": 2**53 - 1 + 1800}

        def unexpected(r):
            self.fail("malformed receipt reached external authority")

        with self.assertRaises(Rejected):
            self.clean(receipt, authorize=unexpected)

    def test_visibility_changes_on_final_listing_before_each_upload(self):
        for count in range(5):
            self.api = StoreAPI()

            def publish_repo(method, path, rows):
                if path == "/releases/71/assets?per_page=6" and len(rows) == count:
                    self.api.repo.update(private=False, visibility="public")
                return rows

            self.api.hook = publish_repo
            with self.subTest(already_uploaded=count):
                with self.assertRaises(Rejected):
                    self.publish()
                self.assertEqual(sum(m == "UPLOAD" for m, _ in self.api.mutations), count)

    def test_terminal_cleanup_with_new_unrelated_releases_preserves_all_siblings(self):
        for size in (20, 21, 99):
            self.api = StoreAPI()
            others = [dict(id=1000 + i, tag_name=f"other-{i}") for i in range(size - 1)]
            self.api.sibling = others[:18]
            receipt = self.publish()
            self.api.sibling.extend(others[18:])
            with self.subTest(size=size):
                self.clean(receipt)
                self.assertEqual(self.api.sibling, others)
                self.assertIsNone(self.api.release)
                self.assertIsNone(self.api.tag)
                self.assertFalse(self.api.assets)

    def test_unrelated_releases_added_mid_cleanup_allow_final_tag_readback(self):
        self.api.sibling = [dict(id=1000 + i, tag_name=f"other-{i}") for i in range(18)]
        receipt = self.publish()

        def add_releases(method, path, result):
            if method == "DELETE" and path == "/releases/71":
                self.api.sibling.extend(
                    [dict(id=1200, tag_name="later"), dict(id=1201, tag_name="latest")]
                )
            return result

        self.api.hook = add_releases
        self.clean(receipt)
        self.assertEqual(len(self.api.sibling), 20)
        self.assertIsNone(self.api.release)
        self.assertIsNone(self.api.tag)

    def test_ambiguous_draft_after_first_twenty_and_full_listing_refuse_all_deletion(self):
        for count, ambiguous in ((21, True), (99, False), (100, False)):
            self.api = StoreAPI()
            receipt = self.publish()
            self.api.sibling = [dict(id=1000 + i, tag_name=f"other-{i}") for i in range(count)]
            if ambiguous:
                self.api.sibling[-1].update(tag_name=TAG, draft=True)
            before = list(self.api.mutations)
            with self.subTest(count=count, ambiguous=ambiguous), self.assertRaises(Rejected):
                self.clean(receipt)
            self.assertEqual(before, self.api.mutations)


if __name__ == "__main__":
    unittest.main()
