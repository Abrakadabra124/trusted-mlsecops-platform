import importlib.metadata
import signal
import sys

from mlsecops.contracts import Rejected, canonical
from mlsecops.process_privacy import enforce as enforce_privacy


def serve(source, destination, diagnostic, arm_timeout=lambda: None):
    def emit(request, **fields):
        payload = protocol.response(request, **fields)
        protocol.verify_reply(request, payload)
        content = canonical(payload) + b"\n"
        if len(content) > protocol.MAX_FRAME:
            raise Rejected("serving_response_limit")
        destination.write(content)
        destination.flush()

    try:
        from mlsecops import serving_protocol as protocol
        from mlsecops.model import predict
        from mlsecops.model import session as load_model

        arm_timeout()
        initial = protocol.frame(source, protocol.MAX_LOAD)
        content = protocol.validate(initial)
        if initial["action"] != "load":
            raise Rejected("serving_initial_load_required")
        runtime, scan = load_model(content)
        emit(
            initial,
            ready=True,
            scan=scan,
            runtime_version=importlib.metadata.version("onnxruntime"),
        )
        while True:
            arm_timeout()
            request = protocol.frame(source, protocol.MAX_FRAME)
            if request is None:
                return 0
            protocol.validate(request)
            if request["action"] == "load" or any(
                request[name] != initial[name] for name in ("session_id", "model_sha256")
            ):
                raise Rejected("serving_session_mismatch")
            if request["action"] == "ping":
                emit(request, ready=True)
            else:
                scores = predict(runtime, request["features"])
                emit(
                    request,
                    predictions=[
                        {"row_id": f"{request['request_id']}:{index}", "score": score}
                        for index, score in enumerate(scores)
                    ],
                )
    except Exception:
        diagnostic.write("serving_worker_rejected\n")
        return 1


def main():
    try:
        enforce_privacy()
    except Rejected:
        sys.stderr.write("serving_worker_rejected\n")
        return 1
    return serve(sys.stdin.buffer, sys.stdout.buffer, sys.stderr, lambda: signal.alarm(120))


if __name__ == "__main__":
    raise SystemExit(main())
