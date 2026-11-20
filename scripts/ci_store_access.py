"""Verify private repository Contents reads without sending secrets to another host."""

import os
import sys

from mlsecops.contracts import Rejected
from scripts import ci_private_assets as store
from scripts.ci_asset_http import Client


def check(api, role):
    if role not in ("reader", "publisher"):
        raise Rejected("private_access_role")
    # Both roles require Contents read. Real publication qualifies the write permission.
    store._head(api)


def main(arguments):
    token = os.environ.pop("CANDIDATE_ACCESS_TOKEN", "")
    try:
        if len(arguments) != 1 or not token.startswith("github_pat_"):
            raise Rejected("private_access_credential")
        check(Client(token), arguments[0])
    except Rejected:
        print("private_access_readback=refused")
        return 1
    print("private_access_readback=pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
