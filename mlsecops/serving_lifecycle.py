class Middleware:
    def __init__(self, app):
        self.app = app
        self.lifecycle_failed = False

    def __getattr__(self, name):
        return getattr(self.app, name)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "lifespan":
            await self.app(scope, receive, send)
            return
        phase = "startup"

        async def private_send(message):
            nonlocal phase
            kind = message["type"]
            if kind in ("lifespan.startup.failed", "lifespan.shutdown.failed"):
                self.lifecycle_failed = True
                message = {"type": kind, "message": "serving_lifecycle_rejected"}
            await send(message)
            if kind == "lifespan.startup.complete":
                phase = "shutdown"
            else:
                phase = None

        try:
            await self.app(scope, receive, private_send)
        except BaseException:
            self.lifecycle_failed = True
            if phase is not None:
                await send(
                    {"type": f"lifespan.{phase}.failed", "message": "serving_lifecycle_rejected"}
                )
