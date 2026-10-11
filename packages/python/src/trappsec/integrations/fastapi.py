from .starlette import StarletteIntegration, TrapConflictError, _norm_path  # noqa: F401


class FastAPIIntegration(StarletteIntegration):
    """FastAPI integration.

    Shares the ASGI-level machinery of the Starlette integration: every matched
    route (defined before or after ``Sentry(app)``, directly on the app or via
    ``include_router``) is wrapped at ``route.app`` when bootstrap runs, and the
    request body is replayed to FastAPI after inspection, so no private Starlette
    ``Request`` attributes are mutated. Bootstrap runs on the first request or
    lifespan scope, so ``TestClient`` without ``with`` is protected too.
    """

    def _build_trap_routes(self, traps):
        from functools import partial
        from fastapi import Request, Response
        from fastapi.routing import APIRoute

        async def endpoint(req: Request, trap):
            try:
                response_body, response_config = self.ts._trigger_trap_event(req, trap)
            except Exception as e:
                self.ts.logger.error("trappsec trap handling failed: %s", e)
                response_body, response_config = self.ts._trap_fallback(trap)

            return Response(response_body,
                status_code=response_config["status_code"],
                media_type=response_config["mime_type"])

        return [
            APIRoute(trap["path"], partial(endpoint, trap=trap),
                methods=trap["methods"], name="trappsec_%d" % idx, include_in_schema=False)
            for idx, trap in enumerate(traps)
        ]

    # -------------------------------------------------- included routers (new)
    #
    # Recent FastAPI versions keep ``include_router`` routes lazily inside
    # ``_IncludedRouter`` objects instead of copying them onto the app, and build
    # their handlers from each original route's ``get_route_handler()`` (the
    # public custom-route hook). Older versions copy the routes, in which case
    # the base class already wraps them through ``route.app``.

    @staticmethod
    def _is_included_router(route):
        return hasattr(route, "original_router") and hasattr(route, "include_context")

    def _included_existing(self, routes):
        for route in routes:
            if not self._is_included_router(route):
                continue
            try:
                for ctx in route.effective_route_contexts():
                    path = getattr(ctx, "path", "")
                    methods = getattr(ctx, "methods", None)
                    if path and methods:
                        yield _norm_path(path), methods
            except Exception as e:
                self.ts.logger.warning("trappsec: could not inspect included router: %s", e)

    def _check_conflicts(self, traps):
        super()._check_conflicts(traps)
        existing = list(self._included_existing(self.app.router.routes))
        for trap in traps:
            wanted = set(m.upper() for m in trap["methods"])
            for path, methods in existing:
                if path == _norm_path(trap["path"]) and set(methods) & wanted:
                    raise TrapConflictError(
                        "trappsec error: trap %s %s duplicates an existing route."
                        % (sorted(wanted), trap["path"])
                    )

    def _wrap_routes(self, routes):
        super()._wrap_routes(routes)
        self._wrap_included(routes, set())

    def _wrap_included(self, routes, seen):
        from fastapi.routing import APIRoute

        for route in routes:
            if getattr(route, "routes", None) is not None and not hasattr(route, "endpoint"):
                self._wrap_included(list(route.routes), seen)  # mounts
                continue
            if not self._is_included_router(route):
                continue
            # Drop effective-route caches so handlers are rebuilt through our hook.
            for attr in ("_effective_candidates_version", "_effective_low_priority_routes_version"):
                if hasattr(route, attr):
                    setattr(route, attr, None)
            router = route.original_router
            if id(router) in seen:
                continue
            seen.add(id(router))
            for inner in list(router.routes):
                if self._is_included_router(inner):
                    self._wrap_included([inner], seen)
                elif isinstance(inner, APIRoute):
                    self._patch_route_handler(inner)

    def _patch_route_handler(self, route):
        if getattr(route, "_trappsec_patched", False):
            return
        original = route.get_route_handler
        integration = self

        def get_route_handler():
            handler = original()

            async def trappsec_handler(request):
                from starlette.requests import Request
                try:
                    scope = request.scope
                    ctx = (scope.get("fastapi") or {}).get("effective_route_context")
                    pattern = getattr(ctx, "path", None) or route.path
                    watch = integration.watch_map.get(_norm_path(pattern))
                    if watch is not None:
                        new_scope, new_receive = await integration._inspect(scope, request.receive, watch)
                        if new_scope is not scope or new_receive is not request.receive:
                            request = Request(new_scope, new_receive, getattr(request, "_send", None) or _noop_send)
                except Exception as e:
                    integration.ts.logger.error("trappsec watch failed: %s", e)
                return await handler(request)

            return trappsec_handler

        route.get_route_handler = get_route_handler
        route._trappsec_patched = True


async def _noop_send(message):
    return None
