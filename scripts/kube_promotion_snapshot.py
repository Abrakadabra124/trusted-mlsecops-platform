"""One read-only SQL statement covers both CAS and the promotion journal."""

from mlsecops import kube_storage, promotion_recovery, promotion_state, storage_snapshot
from mlsecops.contracts import decode, require_fields


def read(state):
    version = promotion_state.migration_version(state, kube_storage.admin)
    query = (
        "SELECT jsonb_build_object('objects', ("
        + storage_snapshot.ledger_sql()
        + "), 'promotion', ("
        + promotion_recovery.ledger_sql(version)
        + "));"
    )
    result = decode(kube_storage.admin(state, query))
    require_fields(result, ("objects", "promotion"))
    promotion_recovery.validate_combined(result["objects"], result["promotion"], version=version)
    return result
