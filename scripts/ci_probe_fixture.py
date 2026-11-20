"""Owner-side create/retire of the empty private prerelease for a scoped access check."""

import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mlsecops import signing
from mlsecops.contracts import Rejected, canonical, decode, read_json, require_fields, write_json
from scripts import ci_private_assets as store
from scripts.ci_source_image_native import same

KIND = "store-access-probe"
LOCAL = "fixture.json"


def need(ok):
    if not ok:
        raise Rejected("probe_fixture_unconfirmed")


class Gh:
    """Use the local authenticated CLI with a fixed host. Never obtain its credential."""

    def json(self, method, path, *, body=None, absent=False):
        need(path == store.ROOT or path.startswith(store.ROOT + "/"))
        args = ["gh", "api", "--hostname", "github.com", "--include", "--method", method, path]
        if body is not None:
            args += ["--input", "-"]
        result = subprocess.run(
            args,
            input=canonical(body) if body is not None else b"",
            capture_output=True,
            timeout=45,
            check=False,
        )
        header, sep, raw = result.stdout.replace(b"\r\n", b"\n").partition(b"\n\n")
        match = re.fullmatch(rb"HTTP/[^ ]+ ([0-9]{3})(?: [^\n]*)?", header.split(b"\n")[0])
        need(sep and match)
        status = int(match[1])
        if method == "GET" and absent and status == 404:
            return None
        need(
            result.returncode == 0
            and status == {"GET": 200, "POST": 201, "PATCH": 200, "DELETE": 204}[method]
        )
        need(len(raw) < 2 * 1024 * 1024)
        return decode(raw, 2 * 1024 * 1024) if raw.strip() else {}


def tag_for(nonce):
    need(type(nonce) is str and re.fullmatch("[0-9a-f]{32}", nonce))
    return "ci-access-" + nonce


def live(api, state):
    store._repo(api)
    d = state["descriptor"]
    tag = tag_for(d["nonce"])
    path = store.ROOT + "/releases/" + str(store._number(d["release_id"]))
    row = api.json("GET", path, absent=True)
    ids = store._visible_releases(api, tag)
    by_tag = api.json("GET", store.ROOT + "/releases/tags/" + tag, absent=True)
    if row is None:
        need(ids == [] and by_tag is None)
        return None
    need(ids == [d["release_id"]])
    for observed in (row, by_tag):
        same(
            observed,
            dict(
                id=d["release_id"],
                name=tag,
                tag_name=tag,
                target_commitish=d["target_commitish"],
                draft=False,
                prerelease=True,
                immutable=False,
            ),
        )
    return row


def empty(api, state, row):
    d = state["descriptor"]
    path = store.ROOT + "/releases/" + str(d["release_id"])
    need(row["assets"] == [] and api.json("GET", path + "/assets?per_page=6") == [])


def create(api, folder):
    head = store._head(api)
    nonce = secrets.token_hex(16)
    tag = tag_for(nonce)
    ref = "tags/" + tag
    need(store._visible_releases(api, tag, publishing=True) == [])
    need(api.json("GET", store.ROOT + "/releases/tags/" + tag, absent=True) is None)
    need(api.json("GET", store.ROOT + "/git/ref/" + ref, absent=True) is None)
    folder.mkdir(mode=0o700, exist_ok=False)
    descriptor = dict(
        nonce=nonce, repository_id=store.REPOSITORY_ID, release_id=None, target_commitish=head
    )
    state = dict(stage="reserved-locally", descriptor=descriptor, public=None, signed_body=None)

    def save(stage):
        state["stage"] = stage
        write_json(folder / LOCAL, state)

    save("reserved-locally")
    tagrow = api.json("POST", store.ROOT + "/git/refs", body={"ref": "refs/" + ref, "sha": head})
    store._ref(tagrow, ref, head)
    save("tag")
    store._ref(api.json("GET", store.ROOT + "/git/ref/" + ref), ref, head)
    row = api.json(
        "POST",
        store.ROOT + "/releases",
        body=dict(
            tag_name=tag,
            name=tag,
            target_commitish=head,
            body=tag,
            draft=False,
            prerelease=True,
            make_latest="false",
        ),
    )
    descriptor["release_id"] = store._number(row.get("id"))
    save("release")
    row = live(api, state)
    need(row is not None and row["body"] == tag)
    empty(api, state, row)
    with TemporaryDirectory(prefix="issuer-", dir=folder) as temp:
        signer = Path(temp) / "issuer.pem"
        state["public"] = signing.create_key(signer)
        signed = signing.sign(descriptor, KIND, signer)
        need(signing.verify(signed, KIND, state["public"]) == descriptor)
        state["signed_body"] = canonical(signed).decode("ascii")
    save("signing")
    api.json(
        "PATCH",
        store.ROOT + "/releases/" + str(descriptor["release_id"]),
        body={"body": state["signed_body"]},
    )
    row = live(api, state)
    need(row is not None and row["body"] == state["signed_body"])
    empty(api, state, row)
    save("ready")
    return nonce, state["public"]


def confirm(api, folder):
    """Reconcile an ambiguous PATCH response using the operator's original signed bytes."""
    state = read_json(folder / LOCAL)
    need(state["stage"] in ("signing", "ready"))
    record = state["descriptor"]
    tag = tag_for(record["nonce"])
    need(record["repository_id"] == store.REPOSITORY_ID)
    need(signing.verify(decode(state["signed_body"].encode()), KIND, state["public"]) == record)
    row = live(api, state)
    need(row is not None and row.get("body") == state["signed_body"])
    empty(api, state, row)
    store._ref(
        api.json("GET", store.ROOT + "/git/ref/tags/" + tag),
        "tags/" + tag,
        record["target_commitish"],
    )
    state["stage"] = "ready"
    write_json(folder / LOCAL, state)
    return record["nonce"], state["public"]


def retire(api, folder):
    state = read_json(folder / LOCAL)
    require_fields(state, ("stage", "descriptor", "public", "signed_body"))
    d = state["descriptor"]
    require_fields(d, ("nonce", "repository_id", "release_id", "target_commitish"))
    need(d["repository_id"] == store.REPOSITORY_ID)
    tag = tag_for(d["nonce"])
    head = store._hex(d["target_commitish"], 40)
    ref = "tags/" + tag
    store._repo(api)
    row = api.json("GET", store.ROOT + "/git/ref/" + ref, absent=True)
    if row is not None:
        store._ref(row, ref, head)
    stage = state["stage"]
    need(stage in ("tag", "release", "signing", "ready", "retiring", "retired"))
    if d["release_id"] is None:
        need(stage in ("tag", "retiring", "retired") and store._visible_releases(api, tag) == [])
        need(api.json("GET", store.ROOT + "/releases/tags/" + tag, absent=True) is None)
    else:
        row = live(api, state)
        if row is not None:
            need(stage != "retired")
            allowed = [tag] if stage in ("release", "signing", "retiring") else []
            if state["signed_body"] is not None:
                need(
                    signing.verify(decode(state["signed_body"].encode()), KIND, state["public"])
                    == d
                )
                allowed.append(state["signed_body"])
            need(row["body"] in allowed)
            empty(api, state, row)
            state["stage"] = "retiring"
            write_json(folder / LOCAL, state)
            api.json("DELETE", store.ROOT + "/releases/" + str(d["release_id"]))
            need(live(api, state) is None)
        else:
            need(stage in ("retiring", "retired"))
    tagrow = api.json("GET", store.ROOT + "/git/ref/" + ref, absent=True)
    if tagrow is not None:
        need(stage != "retired")
        store._ref(tagrow, ref, head)
        api.json("DELETE", store.ROOT + "/git/refs/" + ref)
    need(api.json("GET", store.ROOT + "/git/ref/" + ref, absent=True) is None)
    state["stage"] = "retired"
    write_json(folder / LOCAL, state)


def main(args):
    try:
        need(
            len(args) == 2
            and args[0] in ("create", "confirm", "retire")
            and not os.environ.get("GITHUB_ACTIONS")
        )
        folder = Path(args[1])
        need(
            folder.is_absolute()
            and folder == folder.resolve()
            and folder.parent.is_dir()
            and not folder.is_relative_to(Path(__file__).resolve().parents[1])
        )
        if args[0] in ("create", "confirm"):
            operation = create if args[0] == "create" else confirm
            nonce, public = operation(Gh(), folder)
            print("probe_nonce=" + nonce)
            print("probe_public=" + public)
        else:
            retire(Gh(), folder)
        print("fixture_" + args[0] + "=pass")
        return 0
    except (Rejected, OSError, KeyError, subprocess.SubprocessError):
        print("fixture_operation=unconfirmed")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
