# Django → Flask Migration Guide: Prowler API

## Pros & Cons

### Pros of Migrating to Flask

| # | Pro |
|---|-----|
| 1 | **Lighter footprint** — No ORM, admin, sessions, sites framework, or other bundled batteries you don't use. Startup time and image size both drop. |
| 2 | **Explicit control** — Every behavior (auth, serialization, filtering) is code you own and can read, rather than DRF/allauth magic resolved through class hierarchies. |
| 3 | **SQLAlchemy 2.x** — Richer query composition, true async with `asyncio` support, finer-grained connection control, and no Django migration lockout during complex schema changes. |
| 4 | **Per-request DB connections are straightforward** — No Django ORM thread-locals or `close_old_connections` workarounds for ASGI; SQLAlchemy sessions are explicit and async-native. |
| 5 | **Smaller cold-start** — Celery workers and health-check containers pay less startup overhead, meaningful at the scale Prowler workers run. |
| 6 | **Fewer hidden abstractions** — Easier to trace a request from URL → view → SQL without reading DRF source. Onboarding time for new engineers decreases. |

### Cons of Migrating to Flask

| # | Con |
|---|-----|
| 1 | **Lose ~15 mature ecosystem packages** — `allauth`, `simplejwt`, `drf-spectacular`, `psqlextra`, `django-celery-beat`, `django-celery-results`, `django-guid`, `django-filter`, `django-cors-headers`, `django-environ`, `django-eventstream`, `dj-rest-auth`, `djangorestframework-jsonapi`, `drf-simple-apikey`, `django-postgres-extra`. Each must be substituted or rebuilt. |
| 2 | **DRF re-implementation cost** — 30+ ViewSets, 80+ serializers, JSON:API compliance, pagination, filtering, throttling, and permission classes all require Flask equivalents. This is the largest single block of work. |
| 3 | **Multi-database router** — The 4-connection router (`default` / `admin` / `replica` / `admin_replica`) with context-variable-based read-replica selection is non-trivial to replicate with SQLAlchemy engine switching. |
| 4 | **Row-Level Security (RLS)** — RLS is currently tied to Django's connection lifecycle and database user switching. This must be precisely reimplemented on SQLAlchemy session events or the security boundary breaks. |
| 5 | **Django migrations → Alembic** — 50+ models, 8 custom enum field types, and 2 PostgreSQL-partitioned tables must all be mapped; migration history must be reconciled without data loss. |
| 6 | **Celery scheduler** — `django-celery-beat` manages periodic tasks through Django admin and the ORM. The replacement (`celery.beat` + `redbeat` or standalone DB scheduler) requires re-provisioning all existing schedules. |
| 7 | **JSON:API compliance** — `djangorestframework-jsonapi` enforces the full JSON:API spec automatically. In Flask, every endpoint's response envelope, error format, relationships, and includes must be manually validated or a less-mature library used. |
| 8 | **SAML / Social login** — `django-allauth` handles Google, GitHub, and SAML with minimal wiring. The Flask equivalents (`authlib`, `python3-saml`) require significantly more manual integration work. |
| 9 | **Management commands** — 3 existing `manage.py` commands must be rewritten as Click scripts. Minor work but a testing and deployment change. |
| 10 | **Test infrastructure rebuild** — `pytest-django`, `django-celery-beat` test support, and DRF test client utilities must all be replaced with `pytest-flask`, SQLAlchemy fixtures, and manual Celery test setup. |
| 11 | **Timeline risk** — Prowler's API surface is large (30+ endpoints, 50+ models, 30+ async tasks). A big-bang rewrite is high-risk; a parallel-run strategy adds operational complexity. |

---

## Overview: What Is Being Migrated

The Prowler API lives at `api/src/backend/`. It is a single-app Django 5.1 project exposing a JSON:API-compliant REST API over PostgreSQL 16, with Celery 5 task workers backed by Valkey (Redis-compatible).

**Scale:**
- 50+ Django ORM models (including 2 PostgreSQL-partitioned tables)
- 30+ DRF ViewSets across `/api/v1/`
- 80+ DRF serializers
- 30+ Celery async tasks
- 4 PostgreSQL database connections (default, admin, replica, admin_replica)
- PostgreSQL Row-Level Security enforced at the DB layer

---

## Section A: Project Layout

### Current Layout (`api/src/backend/`)

```
config/
  django/          # base.py, devel.py, production.py, testing.py
  settings/        # celery.py, eventstream.py, partitions.py, sentry.py, social_login.py
  celery.py
  urls.py
  asgi.py / wsgi.py
  guniconf.py
  custom_logging.py
  env.py
api/
  models.py        # 3,099 lines — all ORM models
  v1/
    views.py       # 8,736 lines — all ViewSets
    serializers.py # 4,300 lines — all serializers
    urls.py
    mixins.py
  authentication.py
  rls.py
  db_router.py
  middleware.py
  signals.py
  exceptions.py
  renderers.py
  rbac/
    permissions.py
  management/
    commands/
tasks/
  tasks.py         # 30+ Celery task definitions
manage.py
```

### Proposed Flask Layout (app factory + blueprints)

```
app/
  __init__.py      # create_app() factory
  config.py        # replaces config/django/
  extensions.py    # db, celery, limiter, cors, etc.
  db/
    base.py        # SQLAlchemy DeclarativeBase
    engine.py      # engine/session factory (4 connections)
    rls.py         # RLS session events
    router.py      # read-replica selection logic
  models/
    user.py
    tenant.py
    provider.py
    scan.py
    finding.py
    # ... one file per domain (split from models.py)
  api/
    v1/
      __init__.py  # register blueprints
      auth/        # token, refresh, switch, social, saml endpoints
      users/
      tenants/
      providers/
      scans/
      findings/
      compliance/
      integrations/
      # ... one blueprint per resource group
  schemas/         # marshmallow or pydantic schemas (replace serializers.py)
  auth/
    jwt.py         # PyJWT RS256 helpers
    api_key.py     # Fernet API key helpers
    social.py      # authlib Google/GitHub
    saml.py        # python3-saml
    decorators.py  # @require_auth, @require_permission
  middleware.py    # before_request / after_request hooks
  exceptions.py    # errorhandler registrations
  cli/             # Click commands (replace manage.py)
    findings.py
    tasks.py
    sites.py
tasks/
  celery_app.py    # Celery instance (no Django dependency)
  tasks.py         # ported task definitions
  base.py          # RLSTask base class
wsgi.py
asgi.py            # if keeping async (uvicorn/hypercorn)
```

---

## Section B: Settings / Configuration

### Replace

| Django | Flask |
|--------|-------|
| `django-environ` | `python-decouple` or `dynaconf` |
| `config/django/base.py` | `app/config.py` with `BaseConfig`, `DevelopmentConfig`, `ProductionConfig`, `TestingConfig` |
| `config/settings/celery.py` | `tasks/celery_app.py` — standalone config dict |
| `config/settings/sentry.py` | `sentry_sdk.init()` in `create_app()` |
| `config/settings/social_login.py` | `authlib` config in `app/auth/social.py` |
| `config/settings/eventstream.py` | `flask-sse` Redis URL config |
| `config/settings/partitions.py` | SQLAlchemy DDL events or raw `CREATE TABLE ... PARTITION BY` |

### Key Environment Variables to Preserve

All variables currently consumed in `config/django/base.py` and `config/env.py` must be re-mapped:

- `SECRET_KEY`, `DJANGO_DEBUG` → `SECRET_KEY`, `FLASK_DEBUG`
- `DATABASE_URL` / multi-DB env vars → SQLAlchemy `SQLALCHEMY_DATABASE_URI` variants per connection
- `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`
- `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` (RS256)
- `SOCIAL_AUTH_GOOGLE_CLIENT_ID/SECRET`, `SOCIAL_AUTH_GITHUB_CLIENT_ID/SECRET`
- `SENTRY_DSN`
- `ALLOWED_HOSTS` → `SESSION_COOKIE_DOMAIN` / CORS origins list
- `DJANGO_CORS_ALLOWED_ORIGINS` → `flask-cors` `CORS_ORIGINS`
- All `LIGHTHOUSE_*` and `NEO4J_*` vars carry over unchanged

---

## Section C: ORM / Database

### Replace Django ORM with SQLAlchemy 2.x

**File to port:** `api/src/backend/api/models.py` (3,099 lines)

#### DeclarativeBase setup (`app/db/base.py`)

```python
from sqlalchemy.orm import DeclarativeBase
import uuid

class Base(DeclarativeBase):
    pass
```

#### Model mapping pattern

Django model:
```python
class Provider(RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    provider = ProviderEnumField()
    alias = models.CharField(max_length=100, blank=True)
    connected = models.BooleanField(null=True)
    inserted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

SQLAlchemy equivalent:
```python
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.base import Base

class Provider(Base):
    __tablename__ = "api_provider"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("api_tenant.id"), nullable=False)
    provider = Column(SAEnum(ProviderEnum, name="provider_enum"), nullable=False)
    alias = Column(String(100), nullable=False, default="")
    connected = Column(Boolean, nullable=True)
    inserted_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    tenant = relationship("Tenant", back_populates="providers")
```

#### Custom enum fields

The 8 custom Django enum fields in `api/src/backend/api/db_utils.py` map to SQLAlchemy `Enum` types:

| Django Custom Field | SQLAlchemy Equivalent |
|--------------------|-----------------------|
| `FindingDeltaEnumField` | `SAEnum(FindingDelta, name="finding_delta_enum")` |
| `IntegrationTypeEnumField` | `SAEnum(IntegrationType, name="integration_type_enum")` |
| `InvitationStateEnumField` | `SAEnum(InvitationState, name="invitation_state_enum")` |
| `MemberRoleEnumField` | `SAEnum(MemberRole, name="member_role_enum")` |
| `ProcessorTypeEnumField` | `SAEnum(ProcessorType, name="processor_type_enum")` |
| `ProviderEnumField` | `SAEnum(ProviderType, name="provider_type_enum")` |
| `ProviderSecretTypeEnumField` | `SAEnum(ProviderSecretType, name="provider_secret_type_enum")` |
| `ScanTriggerEnumField` | `SAEnum(ScanTrigger, name="scan_trigger_enum")` |
| `SeverityEnumField` | `SAEnum(Severity, name="severity_enum")` |
| `StateEnumField` | `SAEnum(State, name="state_enum")` |
| `StatusEnumField` | `SAEnum(Status, name="status_enum")` |

#### PostgreSQL-partitioned tables

`Finding` and `ResourceFindingMapping` use `psqlextra.PostgresPartitionedModel`. SQLAlchemy has no direct equivalent. Two options:

1. **Raw DDL via Alembic** — Emit `CREATE TABLE api_finding (...) PARTITION BY RANGE (inserted_at)` in a migration; SQLAlchemy maps to the table normally, partition management via raw SQL.
2. **`pg_partman`** — Let PostgreSQL's native partition manager handle child table creation; no application-layer change needed.

Both options require the Alembic migration to drop and recreate these tables (with a data migration window) or add partitioning after the fact.

#### 4-Database connection routing

Replace `api/src/backend/api/db_router.py` with SQLAlchemy engine selection via `contextvars`:

```python
# app/db/engine.py
from contextvars import ContextVar
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

_use_replica: ContextVar[bool] = ContextVar("use_replica", default=False)

engines = {
    "default": create_async_engine(settings.DATABASE_URL),
    "admin":   create_async_engine(settings.ADMIN_DATABASE_URL),
    "replica": create_async_engine(settings.REPLICA_DATABASE_URL),
    "admin_replica": create_async_engine(settings.ADMIN_REPLICA_DATABASE_URL),
}

def get_session(use_admin=False) -> AsyncSession:
    if use_admin:
        key = "admin_replica" if _use_replica.get() else "admin"
    else:
        key = "replica" if _use_replica.get() else "default"
    return AsyncSession(engines[key])
```

In the request lifecycle, set `_use_replica` to `True` on `GET` requests (mirrors `db_router.py` behavior).

#### Row-Level Security (RLS)

Current implementation in `api/src/backend/api/rls.py` uses Django's connection lifecycle to set `app.current_tenant_id` for each request.

In SQLAlchemy, use session events:

```python
from sqlalchemy import event, text

@event.listens_for(AsyncSession, "after_begin")
async def set_rls_tenant(session, transaction, connection):
    tenant_id = get_current_tenant_id()  # from contextvars
    if tenant_id:
        await connection.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, TRUE)"),
            {"tid": str(tenant_id)}
        )
```

The PostgreSQL RLS policies themselves (`CREATE POLICY ...`) remain unchanged.

#### Migrations: Django → Alembic

1. Install `alembic` and `alembic-utils`
2. Generate Alembic baseline from current DB state: `alembic revision --autogenerate -m "baseline"`
3. Stamp current DB as current: `alembic stamp head`
4. Future schema changes use `alembic revision --autogenerate`

Do **not** attempt to convert Django migration files to Alembic — generate the baseline from the live schema.

---

## Section D: Authentication & Authorization

### JWT Authentication

**Replace:** `rest_framework_simplejwt` (RS256)
**With:** `PyJWT`

```python
# app/auth/jwt.py
import jwt
from datetime import datetime, timedelta, timezone

def create_access_token(user_id: str, tenant_id: str) -> str:
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm="RS256")

def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
```

Token refresh and blacklist logic (currently in `simplejwt`) must be implemented manually or via a Redis-backed token store.

### API Key Authentication

**Replace:** `drf-simple-apikey`
**With:** Custom `before_request` using the existing Fernet encryption logic

The current key format (`pk_xxxxxxxx.encrypted_key`) and Fernet encryption can be preserved exactly. The authentication class in `api/src/backend/api/authentication.py` (`TenantAPIKeyAuthentication`) becomes a plain Python function called in a Flask `before_request` hook.

### Social Login

**Replace:** `django-allauth` (Google, GitHub, SAML)
**With:**
- Google / GitHub OAuth: `authlib` with `Flask` integration
- SAML: `python3-saml` (same underlying library that `allauth` uses)

```python
# app/auth/social.py
from authlib.integrations.flask_client import OAuth

oauth = OAuth()

def init_app(app):
    oauth.init_app(app)
    oauth.register("google", ...)
    oauth.register("github", ...)
```

SAML configuration (currently in `SAMLConfiguration` model) maps directly to `python3-saml` settings dict — the model structure and DB storage can remain unchanged.

### Combined Auth Decorator

Replaces `CombinedJWTOrAPIKeyAuthentication`:

```python
# app/auth/decorators.py
from functools import wraps
from flask import request, g

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")
        if auth_header.startswith("Bearer "):
            g.user = verify_jwt(auth_header[7:])
        elif api_key_header:
            g.user = verify_api_key(api_key_header)
        else:
            return jsonapi_error(401, "Authentication required")
        return f(*args, **kwargs)
    return decorated
```

### RBAC

**Replace:** `api/src/backend/api/rbac/permissions.py` (`HasPermissions`)
**With:** A Flask decorator that reads `g.user.roles` and checks permissions:

```python
def require_permission(permission: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.user.has_permission(permission):
                return jsonapi_error(403, "Forbidden")
            return f(*args, **kwargs)
        return decorated
    return decorator
```

The `Role` model and its permission fields (`manage_users`, `manage_providers`, etc.) are preserved as-is in SQLAlchemy.

### Password Validation

The 6 validators in Django settings become plain Python functions called in the user creation/update path — no framework dependency required.

---

## Section E: REST API Layer

### ViewSets → Flask Blueprints

**Replace:** 30+ DRF ViewSets in `api/v1/views.py` (8,736 lines)
**With:** Flask blueprints using `flask-smorest` (recommended) or plain `Flask.Blueprint`

`flask-smorest` provides:
- Class-based views (similar to ViewSets)
- Automatic OpenAPI generation from marshmallow schemas
- Request/response validation
- Pagination support

Example migration:

```python
# DRF ViewSet (current)
class ProviderViewSet(BaseRLSViewSet):
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    filterset_fields = {"provider": ["exact"], "alias": ["icontains"]}

    @action(detail=True, methods=["post"])
    def connection_check(self, request, pk=None):
        ...
```

```python
# flask-smorest Blueprint (new)
from flask_smorest import Blueprint
blp = Blueprint("providers", __name__, url_prefix="/api/v1/providers")

@blp.route("/")
class ProviderList(MethodView):
    @require_auth
    @require_permission("manage_providers")
    @blp.arguments(ProviderFilterSchema, location="query")
    @blp.response(200, ProviderSchema(many=True))
    async def get(self, filters):
        return await provider_service.list(filters, tenant_id=g.tenant_id)

    @require_auth
    @blp.arguments(ProviderCreateSchema)
    @blp.response(201, ProviderSchema)
    async def post(self, data):
        return await provider_service.create(data, tenant_id=g.tenant_id)
```

### Serializers → Marshmallow or Pydantic

**Replace:** 80+ DRF serializers in `api/v1/serializers.py` (4,300 lines)
**With:** `marshmallow` schemas (recommended for JSON:API) or `pydantic v2`

`marshmallow-jsonapi` provides JSON:API envelope formatting compatible with the current response format.

Example:
```python
# marshmallow-jsonapi schema
from marshmallow_jsonapi.flask import Schema, Relationship
from marshmallow_jsonapi import fields

class ProviderSchema(Schema):
    class Meta:
        type_ = "providers"
        self_view = "providers.provider_detail"
        self_view_kwargs = {"provider_id": "<id>"}

    id = fields.UUID()
    alias = fields.Str()
    provider = fields.Str()
    connected = fields.Bool(allow_none=True)
    tenant = Relationship(type_="tenants", schema="TenantSchema")
```

### Filtering

**Replace:** `django-filter` (`DjangoFilterBackend`)
**With:** Manual SQLAlchemy filter construction from query parameters

The current `filterset_fields` on each ViewSet becomes explicit filter logic in a service layer:

```python
def apply_filters(query, params: dict):
    if alias := params.get("filter[alias]"):
        query = query.filter(Provider.alias.ilike(f"%{alias}%"))
    if provider_type := params.get("filter[provider]"):
        query = query.filter(Provider.provider == provider_type)
    return query
```

### Pagination

**Replace:** `JsonApiPageNumberPagination`
**With:** SQLAlchemy `.limit()` / `.offset()` with a JSON:API page envelope

```python
def paginate(query, page_number=1, page_size=10):
    total = query.count()
    items = query.offset((page_number - 1) * page_size).limit(page_size).all()
    return {
        "data": items,
        "meta": {"total": total, "page": page_number, "size": page_size},
        "links": { ... }
    }
```

### Throttling

**Replace:** DRF `ScopedRateThrottle`
**With:** `flask-limiter`

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# Per-route
@blp.route("/tokens")
@limiter.limit("10/minute")
def obtain_token():
    ...
```

Current throttle scopes and limits (from `REST_FRAMEWORK.DEFAULT_THROTTLE_RATES`) must be ported individually to limiter decorators.

### CORS

**Replace:** `django-cors-headers`
**With:** `flask-cors`

```python
from flask_cors import CORS
CORS(app, origins=settings.CORS_ALLOWED_ORIGINS, supports_credentials=True)
```

### OpenAPI / Docs

**Replace:** `drf-spectacular` + `drf-spectacular-jsonapi`
**With:** `flask-smorest` (uses `apispec` under the hood) or `flasgger`

`flask-smorest` auto-generates OpenAPI 3.0 from marshmallow schemas and method docstrings, providing a similar experience to `drf-spectacular`. The ReDoc endpoint at `/api/v1/docs` can be replicated with a static HTML template pointing at the generated schema.

---

## Section F: Middleware

### Replace `APILoggingMiddleware`

Current: `api/src/backend/api/middleware.py` — logs request method, path, status, user, tenant.

```python
# app/middleware.py
from flask import g, request
import logging, time

def register_middleware(app):
    @app.before_request
    def before():
        g.start_time = time.monotonic()
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    @app.after_request
    def after(response):
        duration = time.monotonic() - g.start_time
        logger.info(
            "method=%s path=%s status=%d duration=%.3fs user=%s tenant=%s request_id=%s",
            request.method, request.path, response.status_code, duration,
            getattr(g, "user_id", None), getattr(g, "tenant_id", None), g.request_id,
        )
        response.headers["X-Request-ID"] = g.request_id
        return response
```

### Replace `CloseDBConnectionsMiddleware`

SQLAlchemy handles this via `teardown_appcontext`:

```python
@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
```

### Replace `django-guid`

Replace with `g.request_id` set in `before_request` (see logging middleware above). Propagate to Celery tasks via task headers.

---

## Section G: Celery / Task Queue

Celery itself requires no changes. Remove Django-specific integration packages.

### Remove

- `django-celery-beat` — Remove. Replace with one of:
  - **`redbeat`** (Redis-backed beat scheduler) — Recommended; no DB required
  - **`celery.backends.database`** with standalone SQLAlchemy tables
- `django-celery-results` — Remove. Replace with:
  - Redis result backend (`redis://...`) — Simplest
  - `celery-sqlalchemy-scheduler` if DB storage is required

### New Celery App (`tasks/celery_app.py`)

```python
from celery import Celery

def make_celery(app=None):
    celery = Celery(
        "prowler",
        broker=settings.CELERY_BROKER_URL,
        backend=settings.CELERY_RESULT_BACKEND,
        include=["tasks.tasks"],
    )
    celery.conf.update(
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_soft_time_limit=21600,
        task_time_limit=23400,
    )
    return celery

celery = make_celery()
```

### Rewrite `RLSTask` Base Class

Current: `tasks/tasks.py` — integrates with Django ORM to set tenant context and track tasks in `api.Task` model.

New version uses SQLAlchemy session and the `contextvars`-based tenant context:

```python
# tasks/base.py
from celery import Task
from app.db.engine import get_session
from app.db.rls import set_tenant_context

class RLSTask(Task):
    abstract = True

    def __call__(self, *args, **kwargs):
        tenant_id = kwargs.pop("tenant_id", None)
        with get_session() as session:
            set_tenant_context(tenant_id)
            return super().__call__(*args, session=session, **kwargs)
```

All 30+ tasks in `tasks/tasks.py` keep their logic; update imports from Django ORM to SQLAlchemy session calls.

### Scheduled Tasks

Re-register all periodic tasks (currently in `django-celery-beat` DB records) as `redbeat` or static `beat_schedule` entries in the Celery config. Export existing schedules before migration.

---

## Section H: Server-Sent Events

**Replace:** `django-eventstream`
**With:** `flask-sse` (Redis pub/sub) or generator-based SSE

```python
# flask-sse approach
from flask_sse import sse

app.register_blueprint(sse, url_prefix="/api/v1/events")

# Publisher (from Celery task or view):
sse.publish({"scan_id": str(scan.id), "status": "completed"}, type="scan_update")
```

The `SSEAuthentication` class (currently supports JWT via query param for `EventSource`) becomes a `before_request` check on the SSE blueprint.

---

## Section I: Management Commands

**Replace:** `manage.py` custom commands
**With:** Click CLI scripts

```python
# cli/tasks.py
import click
from app import create_app

@click.group()
def cli():
    pass

@cli.command()
def reconcile_orphan_tasks():
    """Detect and fix orphaned Celery tasks."""
    app = create_app()
    with app.app_context():
        # port logic from api/management/commands/reconcile_orphan_tasks.py
        ...

if __name__ == "__main__":
    cli()
```

Register CLI groups in `create_app()`:

```python
from cli.tasks import cli as tasks_cli
app.cli.add_command(tasks_cli)
```

### Commands to Port

| Django Command | File | New CLI Command |
|---------------|------|-----------------|
| `check_and_fix_socialaccount_sites_migration` | `api/management/commands/check_and_fix_socialaccount_sites_migration.py` | `flask sites fix` |
| `findings` | `api/management/commands/findings.py` | `flask findings <subcommand>` |
| `reconcile_orphan_tasks` | `api/management/commands/reconcile_orphan_tasks.py` | `flask tasks reconcile` |

---

## Section J: Exception Handling

**Replace:** `api/src/backend/api/exceptions.py` + DRF `EXCEPTION_HANDLER`
**With:** Flask `errorhandler` decorators

```python
# app/exceptions.py
from flask import jsonify

def register_error_handlers(app):
    @app.errorhandler(ConflictException)
    def handle_conflict(e):
        return jsonapi_error_response(409, e.detail), 409

    @app.errorhandler(InvitationTokenExpiredException)
    def handle_expired(e):
        return jsonapi_error_response(410, e.detail), 410

    @app.errorhandler(422)
    def handle_validation(e):
        return jsonapi_error_response(422, str(e)), 422

def jsonapi_error_response(status: int, detail: str):
    return jsonify({
        "errors": [{"status": str(status), "detail": detail}]
    })
```

All custom exceptions (`ConflictException`, `TaskFailedException`, `ProviderConnectionError`, etc.) are plain Python classes — no framework dependency — and carry over unchanged.

---

## Section K: Testing

### Replace

| Current | Replacement |
|---------|-------------|
| `pytest-django` | `pytest-flask` |
| `django.test.Client` | `app.test_client()` |
| `@pytest.mark.django_db` | SQLAlchemy transactional fixtures |
| Django DB fixtures / factories | `factory-boy` + SQLAlchemy |
| `pytest-celery[redis]` | `celery.contrib.pytest` (built-in) |

### Test Setup Pattern

```python
# conftest.py
import pytest
from app import create_app
from app.db.engine import Base, engine

@pytest.fixture(scope="session")
def app():
    app = create_app("testing")
    with app.app_context():
        Base.metadata.create_all(engine)
        yield app
        Base.metadata.drop_all(engine)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture(autouse=True)
def db_session(app):
    with get_session() as session:
        yield session
        session.rollback()
```

---

## Section L: Dependency Substitution Table

| Current Django Package | Version | Flask Replacement | Notes |
|----------------------|---------|-------------------|-------|
| `django` | 5.1.15 | `flask` | Core framework |
| `djangorestframework` | 3.15.2 | `flask-smorest` | ViewSets → Blueprints |
| `drf-nested-routers` | 0.95.0 | nested Flask blueprints | Manual nesting |
| `drf-spectacular` | 0.27.2 | `flask-smorest` / `apispec` | OpenAPI generation |
| `drf-spectacular-jsonapi` | 0.5.1 | `marshmallow-jsonapi` | JSON:API schema |
| `djangorestframework-jsonapi` | 7.0.2 | `marshmallow-jsonapi` | JSON:API compliance |
| `djangorestframework-simplejwt` | 5.5.1 | `PyJWT` | RS256 JWT |
| `drf-simple-apikey` | 2.2.1 | custom `before_request` | Fernet key logic preserved |
| `dj-rest-auth` | 7.0.1 | custom auth views | Token obtain/refresh endpoints |
| `django-allauth` | 65.15.0 | `authlib` + `python3-saml` | Google, GitHub, SAML |
| `django-postgres-extra` | 2.0.9 | raw DDL in Alembic | Partitioning via pg_partman |
| `django-environ` | 0.11.2 | `python-decouple` | Env var management |
| `django-guid` | 3.5.0 | `g.request_id` in `before_request` | Transaction ID tracking |
| `django-celery-beat` | 2.9.0 | `redbeat` | Periodic task scheduler |
| `django-celery-results` | 2.6.0 | Redis backend or `celery-sqlalchemy-results` | Task result storage |
| `django-cors-headers` | 4.4.0 | `flask-cors` | CORS middleware |
| `django-filter` | 24.3 | manual SQLAlchemy filters | Per-endpoint filter logic |
| `django-eventstream` | 5.3.3 | `flask-sse` | Server-Sent Events |
| `psycopg2-binary` | 2.9.9 | `asyncpg` or `psycopg[binary]` | PostgreSQL driver |
| `sentry-sdk[django]` | 2.56.0 | `sentry-sdk[flask]` | Drop-in with different integration |
| `gunicorn` | 26.0.0 | `gunicorn` | Unchanged |
| `celery` | 5.6.2 | `celery` | Unchanged |
| `pytest-django` | 4.8.0 | `pytest-flask` | Test fixtures |
| `neo4j` | 6.1.0 | `neo4j` | Unchanged |
| `openai` | 1.109.1 | `openai` | Unchanged |
| `matplotlib` | 3.10.8 | `matplotlib` | Unchanged |
| `reportlab` | 4.4.10 | `reportlab` | Unchanged |

---

## Section M: Phased Migration Approach

A big-bang rewrite risks prolonged instability. The recommended approach is an incremental migration running both apps in parallel behind the same API gateway (nginx/Caddy) until parity is achieved.

### Phase 1 — Config & Infrastructure (Week 1–2)

- [ ] Set up Flask app factory with `create_app()` pattern
- [ ] Port all environment variables to `python-decouple`
- [ ] Establish SQLAlchemy engine configuration (4 connections)
- [ ] Configure Alembic; generate baseline from live DB
- [ ] Set up `redbeat` or Redis beat scheduler
- [ ] Configure `sentry-sdk[flask]`

### Phase 2 — Models & Database (Week 2–4)

- [ ] Port all 50+ models from `models.py` to SQLAlchemy `DeclarativeBase` subclasses
- [ ] Map all 8 custom enum field types to SQLAlchemy `Enum`
- [ ] Reimplement RLS session events (`set_config` on session open)
- [ ] Reimplement 4-DB engine router using `contextvars`
- [ ] Handle partitioned tables (`Finding`, `ResourceFindingMapping`) via raw DDL
- [ ] Validate Alembic autogenerate output against Django migration state

### Phase 3 — Authentication (Week 4–5)

- [ ] Implement JWT token create/refresh/switch with `PyJWT` (RS256)
- [ ] Port API key auth (Fernet logic from `authentication.py`)
- [ ] Wire `authlib` for Google and GitHub OAuth
- [ ] Wire `python3-saml` for SAML SSO
- [ ] Implement `@require_auth` and `@require_permission` decorators
- [ ] Port password validators
- [ ] Test: JWT flow, API key flow, OAuth flow, SAML flow

### Phase 4 — API Routes (Week 5–10)

Port endpoints in dependency order (least complex first):

- [ ] Health endpoints (`/health/live`, `/health/ready`)
- [ ] Auth endpoints (`/tokens`, `/tokens/refresh`, `/tokens/switch`)
- [ ] Users & Tenants (`/users/`, `/tenants/`, `/tenants/*/memberships/`)
- [ ] Roles & RBAC (`/roles/`, `/users/*/relationships/roles`)
- [ ] Providers & Secrets (`/providers/`, `/providers/secrets/`, `/provider-groups/`)
- [ ] Scans & Tasks (`/scans/`, `/tasks/`, `/schedules/`)
- [ ] Findings & Resources (`/findings/`, `/resources/`, `/mute-rules/`)
- [ ] Compliance (`/compliance-overviews/`, `/overviews/`)
- [ ] Integrations (`/integrations/`)
- [ ] SAML config, Lighthouse config, API key management
- [ ] OpenAPI schema endpoint (`/schema`) and ReDoc (`/docs`)

For each blueprint: port ViewSet → Blueprint, serializer → marshmallow schema, filterset → SQLAlchemy filter function.

### Phase 5 — Middleware & SSE (Week 9–10)

- [ ] Port `APILoggingMiddleware` to `before_request` / `after_request`
- [ ] Port `CloseDBConnectionsMiddleware` to `teardown_appcontext`
- [ ] Port `django-guid` to `g.request_id`
- [ ] Replace `django-eventstream` with `flask-sse`
- [ ] Port `SSEAuthentication` to `before_request` on SSE blueprint

### Phase 6 — Celery Updates (Week 10–11)

- [ ] Remove Django-specific Celery imports from all task files
- [ ] Rewrite `RLSTask` base class with SQLAlchemy session
- [ ] Update all 30+ tasks to use SQLAlchemy sessions
- [ ] Test all task queues (`scans`, `compliance`, `overview`, `deletion`, etc.)
- [ ] Migrate existing periodic task schedules to `redbeat` or static `beat_schedule`
- [ ] Validate task result storage

### Phase 7 — Management Commands (Week 11)

- [ ] Port `reconcile_orphan_tasks` to Click CLI
- [ ] Port `findings` command to Click CLI
- [ ] Port `check_and_fix_socialaccount_sites_migration` to Click CLI

### Phase 8 — Documentation & Finalization (Week 12)

- [ ] Validate OpenAPI schema output matches existing schema
- [ ] Update `docker-compose` and deployment configs
- [ ] Update `pyproject.toml` dependencies
- [ ] Full regression test run
- [ ] Cut over traffic; decommission Django app

---

## Section N: Verification Checklist

After each phase, and before final cutover:

### Schema & Data
- [ ] `alembic upgrade head` runs cleanly against a copy of production DB
- [ ] Table structures match Django migration output (`pg_dump --schema-only`)
- [ ] RLS policies are unchanged and enforced (cross-tenant isolation test)
- [ ] Partitioned tables (`api_finding`, `api_resourcefindingmapping`) have correct child partitions

### Authentication
- [ ] JWT obtain, refresh, and switch-tenant flows work end-to-end
- [ ] API key authentication works (create key, make authenticated request, revoke)
- [ ] Google OAuth roundtrip completes
- [ ] GitHub OAuth roundtrip completes
- [ ] SAML initiate → IdP → callback → JWT completes
- [ ] Unauthenticated requests receive 401 in JSON:API error format

### API Endpoints
- [ ] All 30+ endpoints return JSON:API-compliant responses
- [ ] Pagination (`page[number]`, `page[size]`) works on all list endpoints
- [ ] Filtering (`filter[field]`) works on all filterable endpoints
- [ ] Ordering (`sort`) works on all sortable endpoints
- [ ] Throttle limits enforce correctly (test rate limit on `/tokens`)
- [ ] CORS headers present on cross-origin requests

### Celery
- [ ] `scan-perform` task enqueues, executes, and records result
- [ ] `provider-connection-check` task runs and updates `Provider.connected`
- [ ] Scheduled scan fires at correct interval via `redbeat`
- [ ] Task results are stored and queryable
- [ ] `reconcile-orphan-tasks` recovers a manually orphaned task

### Server-Sent Events
- [ ] SSE connection established with valid JWT
- [ ] Scan completion event received by connected client
- [ ] SSE connection rejected with invalid token (401)

### Health & Observability
- [ ] `/health/live` returns 200
- [ ] `/health/ready` returns 200 (or 503 when DB is unreachable)
- [ ] Sentry receives test error
- [ ] Request IDs appear in logs

---

## Critical Files Reference

| File | Purpose |
|------|---------|
| [api/src/backend/api/models.py](api/src/backend/api/models.py) | All ORM models (3,099 lines) — primary migration surface |
| [api/src/backend/api/v1/views.py](api/src/backend/api/v1/views.py) | All ViewSets (8,736 lines) — port to blueprints |
| [api/src/backend/api/v1/serializers.py](api/src/backend/api/v1/serializers.py) | All serializers (4,300 lines) — port to marshmallow |
| [api/src/backend/api/v1/urls.py](api/src/backend/api/v1/urls.py) | URL routing — port to blueprint registration |
| [api/src/backend/api/authentication.py](api/src/backend/api/authentication.py) | Auth classes — port to decorators |
| [api/src/backend/api/rls.py](api/src/backend/api/rls.py) | Multi-tenancy / RLS — port to SQLAlchemy events |
| [api/src/backend/api/db_router.py](api/src/backend/api/db_router.py) | Multi-DB routing — port to engine context vars |
| [api/src/backend/api/middleware.py](api/src/backend/api/middleware.py) | Middleware — port to before/after_request |
| [api/src/backend/api/rbac/permissions.py](api/src/backend/api/rbac/permissions.py) | RBAC — port to decorators |
| [api/src/backend/api/exceptions.py](api/src/backend/api/exceptions.py) | Custom exceptions — port to errorhandlers |
| [api/src/backend/api/db_utils.py](api/src/backend/api/db_utils.py) | Custom enum fields — map to SQLAlchemy Enum |
| [api/src/backend/tasks/tasks.py](api/src/backend/tasks/tasks.py) | 30+ Celery tasks — update imports, rewrite RLSTask |
| [api/src/backend/config/celery.py](api/src/backend/config/celery.py) | Celery config — port to standalone `celery_app.py` |
| [api/src/backend/config/django/base.py](api/src/backend/config/django/base.py) | All Django settings — port to Flask config class |
| [api/pyproject.toml](api/pyproject.toml) | Dependencies — update per substitution table |
