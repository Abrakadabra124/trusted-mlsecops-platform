"""One read-only SQL statement covers both CAS and the promotion journal."""

from mlsecops import kube_storage, promotion_recovery, storage_snapshot
from mlsecops.contracts import decode, require_fields


def read(state):
    query = (
        "SELECT jsonb_build_object('objects', ("
        + storage_snapshot.ledger_sql()
        + "), 'promotion', ("
        + promotion_recovery.ledger_sql()
        + "));"
    )
    result = decode(kube_storage.admin(state, query))
    require_fields(result, ("objects", "promotion"))
    promotion_recovery.validate_combined(result["objects"], result["promotion"])
    return result
