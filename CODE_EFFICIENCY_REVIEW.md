# Python Code Efficiency Review: Prowler API

This document identifies concrete redundancies, inefficiencies, and streamlining opportunities across the Prowler API backend (`api/src/backend/`). Findings are grouped by layer. Each entry includes the file path, approximate line numbers, the problem, and the recommended fix.

---

## Table of Contents

1. [Database & Model Layer](#1-database--model-layer)
2. [API Layer — Views & Serializers](#2-api-layer--views--serializers)
3. [Celery Tasks & Async](#3-celery-tasks--async)
4. [Authentication & Security](#4-authentication--security)
5. [Configuration & Settings](#5-configuration--settings)

---

## 1. Database & Model Layer

### 1.1 Eleven Near-Identical Enum Field Classes

**File:** `api/src/backend/api/db_utils.py` — lines 540–667

Every custom enum field is a one-liner class that only passes a different string to the parent constructor, but each is written as a full class body:

```python
# Current — repeated 11 times
class MemberRoleEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("member_role", *args, **kwargs)

class ProviderEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("provider", *args, **kwargs)
# ... 9 more identical classes
```

**Recommended fix:** Replace all 11 classes with a factory function:

```python
def _postgres_enum_field(enum_type_name: str):
    class _Field(PostgresEnumField):
        def __init__(self, *args, **kwargs):
            super().__init__(enum_type_name, *args, **kwargs)
    _Field.__name__ = f"{enum_type_name.title().replace('_','')}EnumField"
    return _Field

MemberRoleEnumField          = _postgres_enum_field("member_role")
ProviderEnumField            = _postgres_enum_field("provider")
ScanTriggerEnumField         = _postgres_enum_field("scan_trigger")
StateEnumField               = _postgres_enum_field("state")
FindingDeltaEnumField        = _postgres_enum_field("finding_delta")
SeverityEnumField            = _postgres_enum_field("severity")
StatusEnumField              = _postgres_enum_field("status")
ProviderSecretTypeEnumField  = _postgres_enum_field("provider_secret_type")
InvitationStateEnumField     = _postgres_enum_field("invitation_state")
IntegrationTypeEnumField     = _postgres_enum_field("integration_type")
ProcessorTypeEnumField       = _postgres_enum_field("processor_type")
```

**Reduction:** ~120 lines → 14 lines.

---

### 1.2 Encryption/Decryption Logic Duplicated Across Four Models

**File:** `api/src/backend/api/models.py` — lines ~1315, ~1963, ~2495, ~2674

`ProviderSecret.secret`, `Integration.credentials`, `LighthouseConfiguration.api_key_decoded`, and `LighthouseProviderConfiguration.credentials_decoded` each contain identical Fernet decrypt/encrypt logic with the same `memoryview`/`str`/`bytes` branch:

```python
# Current — identical in 4 places
@property
def secret(self):
    if isinstance(self._secret, memoryview):
        encrypted_bytes = self._secret.tobytes()
    elif isinstance(self._secret, str):
        encrypted_bytes = self._secret.encode()
    else:
        encrypted_bytes = self._secret
    return json.loads(fernet.decrypt(encrypted_bytes).decode())
```

**Recommended fix:** Extract into a mixin:

```python
class EncryptedJSONFieldMixin:
    _encrypted_field: str  # subclass sets: "_secret", "_credentials", etc.

    def _to_encrypted_bytes(self) -> bytes:
        raw = getattr(self, self._encrypted_field)
        if isinstance(raw, memoryview):
            return raw.tobytes()
        if isinstance(raw, str):
            return raw.encode()
        return raw

    def _decrypt(self) -> dict:
        return json.loads(fernet.decrypt(self._to_encrypted_bytes()).decode())

    def _encrypt(self, value: dict | str) -> bytes:
        payload = value if isinstance(value, str) else json.dumps(value)
        return fernet.encrypt(payload.encode())

# Usage
class ProviderSecret(EncryptedJSONFieldMixin, RowLevelSecurityProtectedModel):
    _encrypted_field = "_secret"

    @property
    def secret(self):
        return self._decrypt()

    @secret.setter
    def secret(self, value):
        self._secret = self._encrypt(value)
```

**Reduction:** ~80 lines of duplicated logic → single mixin; any future encryption changes are made in one place.

---

### 1.3 RLS Constraint Definition Duplicated ~30 Times

**File:** `api/src/backend/api/models.py` — throughout

Almost every model repeats the identical `constraints` block verbatim:

```python
# Current — copied into ~30 model Meta classes
class Meta:
    constraints = [
        RowLevelSecurityConstraint(
            field="tenant_id",
            name="rls_on_%(class)s",
            statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
        ),
    ]
```

**Recommended fix:** Promote this to the base class `RowLevelSecurityProtectedModel` so subclasses inherit it automatically. Models that need additional constraints can append:

```python
class RowLevelSecurityProtectedModel(Tenant):
    class Meta:
        abstract = True
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

# Model with extra constraint
class Finding(RowLevelSecurityProtectedModel):
    class Meta(RowLevelSecurityProtectedModel.Meta):
        constraints = RowLevelSecurityProtectedModel.Meta.constraints + [
            RowLevelSecurityConstraint(..., partition_name="default"),
        ]
```

**Reduction:** Eliminates ~90 lines of copy-pasted constraint blocks.

---

### 1.4 N+1 Query in `Finding.add_resources()` Loop

**File:** `api/src/backend/api/models.py` — lines ~1208–1214

`add_resources()` calls `update_or_create()` inside a Python loop, issuing one `SELECT` + one `INSERT/UPDATE` per resource:

```python
# Current — O(n) queries
for resource in resources:
    ResourceFindingMapping.objects.update_or_create(
        resource=resource, finding=self, tenant_id=self.tenant_id
    )
    regions.add(resource.region)
```

**Recommended fix:** Use `bulk_create` with `update_conflicts`:

```python
def add_resources(self, resources: list["Resource"] | None) -> None:
    if not resources:
        return
    mappings = [
        ResourceFindingMapping(
            resource_id=r.id, finding=self, tenant_id=self.tenant_id
        )
        for r in resources
    ]
    ResourceFindingMapping.objects.bulk_create(
        mappings,
        update_conflicts=True,
        unique_fields=["finding_id", "resource_id"],
        update_fields=[],
    )
    self.resource_regions = list({r.region for r in resources} | set(self.resource_regions or []))
    self.resource_services = list({r.service for r in resources} | set(self.resource_services or []))
    self.resource_types = list({r.type for r in resources} | set(self.resource_types or []))
    self.save(update_fields=["resource_regions", "resource_services", "resource_types"])
```

**Impact:** Reduces from N+1 queries to 2 queries regardless of how many resources are associated with a finding — critical for large scans.

---

### 1.5 Redundant `get_queryset()` Override in `ActiveProviderPartitionedManager`

**File:** `api/src/backend/api/models.py` — lines ~129–131

`ActiveProviderPartitionedManager` re-defines `get_queryset()` with identical body to its parent `ActiveProviderManager`, making the override pointless:

```python
# Current
class ActiveProviderPartitionedManager(PostgresManager, ActiveProviderManager):
    def get_queryset(self):
        return super().get_queryset().filter(self.active_provider_filter())  # already done by parent
```

**Recommended fix:** Remove the override entirely. Python MRO will call `ActiveProviderManager.get_queryset()` automatically:

```python
class ActiveProviderPartitionedManager(PostgresManager, ActiveProviderManager):
    pass
```

---

### 1.6 Email Normalization Duplicated in Two `save()` Methods

**File:** `api/src/backend/api/models.py` — lines ~166 and ~1362

`User.save()` and `Invitation.save()` each implement the same strip-and-lowercase logic:

```python
# Current — copied verbatim
def save(self, *args, **kwargs):
    if self.email:
        self.email = self.email.strip().lower()
    super().save(*args, **kwargs)
```

**Recommended fix:** Extract a mixin:

```python
class NormalizedEmailMixin(models.Model):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

class User(NormalizedEmailMixin, AbstractBaseUser): ...
class Invitation(NormalizedEmailMixin, RowLevelSecurityProtectedModel): ...
```

---

### 1.7 `Role` Permission Fields Hardcoded in Two Places

**File:** `api/src/backend/api/models.py` — lines ~1409–1438

`PERMISSION_FIELDS` is a static list referenced in both `permission_state` (property) and `filter_by_permission_state()` (classmethod). Adding a new permission field requires updating the list manually:

```python
# Current — fragile list
PERMISSION_FIELDS = [
    "manage_users", "manage_account", "manage_billing",
    "manage_providers", "manage_integrations", "manage_scans",
]
```

**Recommended fix:** Derive it from the model's own field names at class definition time:

```python
@classmethod
def permission_field_names(cls) -> list[str]:
    return [f.name for f in cls._meta.get_fields() if f.name.startswith("manage_")]
```

This auto-expands as new `manage_*` fields are added.

---

### 1.8 String Concatenation Loop in `RowLevelSecurityConstraint.create_sql()`

**File:** `api/src/backend/api/rls.py` — lines ~78–103

SQL fragments are built with `+=` on strings inside a loop — quadratic allocation on each iteration and hard to read:

```python
# Current
policy_queries = ""
for statement in self.statements:
    clause = f"{'WITH CHECK' if statement == 'INSERT' else 'USING'}"
    policy_queries = f"{policy_queries}{self.policy_sql_query.format(...)}"
```

**Recommended fix:** Collect into a list and join once:

```python
clauses = [
    "WITH CHECK" if s == "INSERT" else "USING"
    for s in self.statements
]
policy_queries = "".join(
    self.policy_sql_query.format(statement=s, clause=c)
    for s, c in zip(self.statements, clauses)
)
grant_queries = "".join(
    self.grant_sql_query.format(statement=s)
    for s in self.statements
)
```

---

### 1.9 Potential SQL Syntax Error in `BaseSecurityConstraint.drop_sql_query`

**File:** `api/src/backend/api/rls.py` — line ~148

The `REVOKE` statement template appears to be missing `FROM` (standard SQL requires `REVOKE ... FROM <role>`). Confirm the template reads:

```sql
REVOKE ALL ON TABLE %(table_name)s FROM %(db_user)s;
```

If the current template uses `TO` instead, this would silently fail or raise a database error on constraint removal.

---

### 1.10 Unused `**hints` Parameters With Suppressed Linter Warnings

**File:** `api/src/backend/api/db_router.py` — lines ~31–62

All four router methods accept `**hints` and annotate `# noqa: F841` to silence the "unused variable" warning. The hints are never inspected:

```python
def db_for_read(self, model, **hints):  # noqa: F841
    ...
```

**Recommended fix:** Either use the hints (e.g., check `hints.get("instance")` for object-specific routing) or remove `**hints` entirely if it serves no purpose:

```python
def db_for_read(self, model, **_hints):
    ...
```

Using `**_hints` (underscore prefix) communicates intent without a noqa comment.

---

## 2. API Layer — Views & Serializers

### 2.1 `get_serializer_class()` Pattern Duplicated Across 6+ ViewSets

**File:** `api/src/backend/api/v1/views.py` — lines ~977, ~1743, ~2055, ~4225, ~4284, ~4421

Every affected ViewSet contains essentially the same action-to-serializer dispatch:

```python
# Current — repeated in UserViewSet, ProviderViewSet, ScanViewSet, etc.
def get_serializer_class(self):
    if self.action == "create":
        return UserCreateSerializer
    elif self.action == "partial_update":
        return UserUpdateSerializer
    return super().get_serializer_class()
```

**Recommended fix:** Add a mixin to `mixins.py`:

```python
class ActionSerializerMixin:
    """Map ViewSet actions to specific serializer classes via `action_serializers` dict."""
    action_serializers: dict[str, type] = {}

    def get_serializer_class(self):
        return self.action_serializers.get(self.action) or super().get_serializer_class()
```

Usage:

```python
class UserViewSet(ActionSerializerMixin, BaseRLSViewSet):
    serializer_class = UserSerializer
    action_serializers = {
        "create": UserCreateSerializer,
        "partial_update": UserUpdateSerializer,
    }
```

**Reduction:** Eliminates ~30 lines of duplicated `get_serializer_class()` bodies.

---

### 2.2 `set_required_permissions()` Repeated With Minor Variations

**File:** `api/src/backend/api/v1/views.py` — multiple ViewSets

ViewSets that allow reads for all roles but gate writes behind a specific permission repeat the same pattern:

```python
# Current — copied across ProviderViewSet, ScanViewSet, ProviderGroupViewSet, etc.
def set_required_permissions(self):
    if self.request.method in SAFE_METHODS:
        self.required_permissions = []
    else:
        self.required_permissions = [Permissions.MANAGE_PROVIDERS]
```

**Recommended fix:** Add to `mixins.py`:

```python
class SafeMethodPermissionMixin:
    """Clears required_permissions on SAFE_METHODS; enforces write_permission otherwise."""
    write_permission: str = None

    def set_required_permissions(self):
        self.required_permissions = [] if self.request.method in SAFE_METHODS else [self.write_permission]
```

Usage:

```python
class ProviderViewSet(SafeMethodPermissionMixin, BaseRLSViewSet):
    write_permission = Permissions.MANAGE_PROVIDERS
```

---

### 2.3 Five Identical Report-Serving Actions in `ScanViewSet`

**File:** `api/src/backend/api/v1/views.py` — lines ~2413–2633

`cis()`, `threatscore()`, `ens()`, `nis2()`, and `csa()` all follow the exact same structure: check task state → verify `output_location` → load file → return response. Each is ~35 lines, totalling ~175 lines.

**Recommended fix:** Extract a private helper:

```python
def _serve_scan_report(self, scan, report_type: str, filename: str, content_type: str):
    if running_resp := self._check_task_running(scan):
        return running_resp
    if not scan.output_location:
        return Response({"detail": "Report not available."}, status=404)
    content = self._load_output(scan.output_location, report_type)
    response = HttpResponse(content, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response

@action(detail=True, methods=["get"])
def cis(self, request, pk=None):
    return self._serve_scan_report(self.get_object(), "cis", "cis_report.pdf", "application/pdf")

@action(detail=True, methods=["get"])
def nis2(self, request, pk=None):
    return self._serve_scan_report(self.get_object(), "nis2", "nis2_report.pdf", "application/pdf")
```

**Reduction:** ~175 lines → ~50 lines.

---

### 2.4 Three Near-Identical `ResourceIdentifierSerializer` Classes

**File:** `api/src/backend/api/v1/serializers.py` — lines ~412, ~783, ~2274

`RoleResourceIdentifierSerializer`, `ProviderResourceIdentifierSerializer`, and `ProviderGroupResourceIdentifierSerializer` each implement the same `to_representation()` / `to_internal_value()` logic swapping `type` ↔ `resource_type`.

**Recommended fix:** Consolidate into one base class:

```python
class ResourceIdentifierSerializer(BaseSerializerV1):
    """JSON:API resource identifier: swaps 'type' to/from 'resource_type'."""
    id = serializers.UUIDField()
    resource_type = serializers.CharField(source="type")

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep["type"] = rep.pop("resource_type", None)
        return rep

    def to_internal_value(self, data):
        data = dict(data)
        data["resource_type"] = data.pop("type", None)
        return super().to_internal_value(data)

class RoleResourceIdentifierSerializer(ResourceIdentifierSerializer):
    class Meta:
        resource_name = "roles"

class ProviderResourceIdentifierSerializer(ResourceIdentifierSerializer):
    class Meta:
        resource_name = "providers"
```

---

### 2.5 Enum Choice Serializer Fields Duplicated ~8 Times

**File:** `api/src/backend/api/v1/serializers.py` — lines ~107, ~616, ~855, ~1006 and others

Each enum serializer field is a trivial subclass of `ChoiceField` that only wires up a choices list:

```python
# Current — repeated for every enum type
class StateEnumSerializerField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs["choices"] = StateChoices.choices
        super().__init__(**kwargs)
```

**Recommended fix:** Use a factory — mirrors the db_utils fix in [1.1](#11-eleven-near-identical-enum-field-classes):

```python
def enum_choice_field(choices_class):
    class _Field(serializers.ChoiceField):
        def __init__(self, **kwargs):
            kwargs["choices"] = choices_class.choices
            super().__init__(**kwargs)
    return _Field

StateEnumSerializerField      = enum_choice_field(StateChoices)
MemberRoleEnumSerializerField = enum_choice_field(Membership.RoleChoices)
ProviderEnumSerializerField   = enum_choice_field(Provider.ProviderChoices)
```

---

### 2.6 Through-Model Relationship Creation Repeated in 4+ Serializers

**File:** `api/src/backend/api/v1/serializers.py` — lines ~719, ~751, ~2150, ~2180

`ProviderGroupCreateSerializer.create()`, `ProviderGroupUpdateSerializer.update()`, `RoleCreateSerializer.create()`, and `RoleUpdateSerializer.update()` all follow: pop related items → loop bulk-create through-model instances.

**Recommended fix:** Extract a reusable helper on `RLSSerializer`:

```python
@staticmethod
def _bulk_set_relationship(through_model, parent_field, related_field,
                            parent, items, tenant_id):
    through_model.objects.filter(**{parent_field: parent}).delete()
    through_model.objects.bulk_create([
        through_model(**{
            parent_field: parent,
            related_field: item,
            "tenant_id": tenant_id,
        })
        for item in items
    ])
```

Replaces 4 near-identical `create/update` methods with a single call.

---

### 2.7 RBAC Visibility Filter Pattern Repeated in 3+ ViewSets

**File:** `api/src/backend/api/v1/views.py` — `ProviderViewSet`, `ScanViewSet`, `ResourceViewSet`

All three apply the same `unlimited_visibility` branch inside `get_queryset()`:

```python
# Current — repeated
if role.unlimited_visibility:
    queryset = Model.objects.all()
else:
    queryset = Model.objects.filter(provider__in=visible_providers)
```

**Recommended fix:** Add to `mixins.py`:

```python
class RBACVisibilityMixin:
    provider_lookup_field = "provider"

    def apply_visibility(self, queryset, role):
        if role.unlimited_visibility:
            return queryset
        return queryset.filter(
            **{f"{self.provider_lookup_field}__in": role.visible_providers()}
        )
```

---

## 3. Celery Tasks & Async

### 3.1 ~30 Thin Wrapper Tasks Repeat the Same One-Line Body

**File:** `api/src/backend/tasks/tasks.py` — throughout

Many tasks exist solely to forward arguments to a job function with no additional logic:

```python
# Current — repeated ~30 times with minor variations
@shared_task(base=RLSTask, name="provider-connection-check")
@set_tenant
def check_provider_connection_task(provider_id: str):
    return check_provider_connection(provider_id=provider_id)

@shared_task(base=RLSTask, name="integration-connection-check")
@set_tenant
def check_integration_connection_task(integration_id: str):
    return check_integration_connection(integration_id=integration_id)
```

**Recommended fix:** Use a factory that creates and registers the task in one call:

```python
def rls_task(job_func, name: str, **task_kwargs):
    """Create a named RLSTask that forwards all kwargs to `job_func`."""
    @shared_task(base=RLSTask, name=name, **task_kwargs)
    @set_tenant
    def _task(**kwargs):
        return job_func(**kwargs)
    _task.__name__ = f"{job_func.__name__}_task"
    return _task

check_provider_connection_task   = rls_task(check_provider_connection,   "provider-connection-check")
check_integration_connection_task = rls_task(check_integration_connection, "integration-connection-check")
check_lighthouse_connection_task  = rls_task(check_lighthouse_connection,  "lighthouse-connection-check")
```

**Reduction:** Collapses ~300 lines of boilerplate wrapper definitions.

---

### 3.2 `visibility_timeout` Set Three Times in Celery Config

**File:** `api/src/backend/config/celery.py` — lines ~19–27

The same constant is assigned to three separate config keys in three separate statements:

```python
# Current
celery_app.conf.broker_transport_options = {"visibility_timeout": BROKER_VISIBILITY_TIMEOUT, ...}
celery_app.conf.result_backend_transport_options = {"visibility_timeout": BROKER_VISIBILITY_TIMEOUT}
celery_app.conf.visibility_timeout = BROKER_VISIBILITY_TIMEOUT
```

**Recommended fix:** Consolidate into a single `conf.update()` call:

```python
celery_app.conf.update(
    broker_transport_options={
        "visibility_timeout": BROKER_VISIBILITY_TIMEOUT,
        "queue_order_strategy": "priority",
    },
    result_backend_transport_options={"visibility_timeout": BROKER_VISIBILITY_TIMEOUT},
    visibility_timeout=BROKER_VISIBILITY_TIMEOUT,
    result_extended=True,
    result_expires=None,
    task_default_priority=6,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
)
```

---

### 3.3 Task Annotation Groups Are Implicit

**File:** `api/src/backend/config/celery.py` — lines ~60–82

Task names are embedded inline inside `task_annotations` dict comprehensions with no explicit grouping. Adding a new task to the "connection check" or "long running" category requires finding the right comprehension:

```python
# Current — groupings are implied, not named
celery_app.conf.task_annotations = {
    **{name: {"soft_time_limit": 60, "time_limit": 120} for name in (
        "provider-connection-check",
        "integration-connection-check",
        # ...
    )},
    **{name: {"soft_time_limit": _LONG_LIMIT, ...} for name in (
        "scan-perform",
        # ...
    )},
}
```

**Recommended fix:** Name the groups as module-level constants:

```python
_CONNECTION_CHECK_TASKS = frozenset({
    "provider-connection-check",
    "integration-connection-check",
    "lighthouse-connection-check",
    "lighthouse-provider-connection-check",
})

_LONG_RUNNING_TASKS = frozenset({
    "scan-perform",
    "scan-perform-scheduled",
    "provider-deletion",
    "tenant-deletion",
})

celery_app.conf.task_annotations = {
    **{n: {"soft_time_limit": 120, "time_limit": 180} for n in _CONNECTION_CHECK_TASKS},
    **{n: {"soft_time_limit": _LONG_SOFT, "time_limit": _LONG_HARD} for n in _LONG_RUNNING_TASKS},
}
```

---

### 3.4 Exception Swallowing in Parallel Tasks Is Not Reusable

**File:** `api/src/backend/tasks/tasks.py` — lines ~918–930

`reset_ephemeral_resource_findings_count_task` catches all exceptions and returns a status dict to prevent cascading chord failures. This pattern is not applied consistently to other tasks in parallel groups and the implementation is inline:

```python
# Current — only applied to one task, inline
try:
    return reset_ephemeral_resource_findings_count(...)
except Exception as exc:
    logger.exception(f"reset_ephemeral_resource_findings_count failed: {exc}")
    return {"status": "failed", "scan_id": str(scan_id), "reason": str(exc)}
```

**Recommended fix:** Create a decorator for tasks that participate in Celery chords/groups:

```python
def chord_safe(func):
    """Return an error-status dict instead of raising, so chord callbacks still run."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            logger.exception("%s failed: %s", func.__name__, exc)
            return {
                "status": "failed",
                "task": func.__name__,
                "reason": str(exc),
                **{k: str(v) for k, v in kwargs.items() if k.endswith("_id")},
            }
    return wrapper
```

Apply to all tasks invoked inside `group()` or `chord()` calls.

---

## 4. Authentication & Security

### 4.1 Duplicate Exception `__init__` Bodies in Five Exception Classes

**File:** `api/src/backend/api/exceptions.py` — lines ~116–237

`UpstreamAuthenticationError`, `UpstreamAccessDeniedError`, `UpstreamServiceUnavailableError`, `UpstreamInternalError`, and `ComplianceWarmingError` each define an identical `__init__`:

```python
# Current — copied 5 times
def __init__(self, detail=None):
    super().__init__(
        detail=[{
            "detail": detail or self.default_detail,
            "status": str(self.status_code),
            "code": self.default_code,
        }]
    )
```

**Recommended fix:** Introduce one intermediate base class:

```python
class StructuredAPIException(APIException):
    """APIException whose detail is always a single-element JSON:API error list."""
    def __init__(self, detail=None):
        super().__init__(detail=[{
            "detail": detail or self.default_detail,
            "status": str(self.status_code),
            "code": self.default_code,
        }])

class UpstreamAuthenticationError(StructuredAPIException):
    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = "Provider credentials are invalid or expired."
    default_code = "upstream_auth_failed"

class UpstreamAccessDeniedError(StructuredAPIException):
    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = "Access denied by the upstream provider."
    default_code = "upstream_access_denied"
# ... etc.
```

**Reduction:** ~110 lines → ~25 lines. Any future exception of this shape is one `default_*` assignment.

---

### 4.2 Admin DB Context Repeated Three Times in `TenantAPIKeyAuthentication`

**File:** `api/src/backend/api/authentication.py` — lines ~29–71

The pattern of switching the model's default manager to the admin DB, performing work, then restoring it appears three separate times in the same class:

```python
# Current — 3 separate usages of the same pattern
original_objects = self.model.objects
self.model.objects = self.model.objects.using(MainRouter.admin_db)
try:
    ...
finally:
    self.model.objects = original_objects
```

**Recommended fix:** Extract a context manager:

```python
from contextlib import contextmanager

@contextmanager
def using_admin_db(model):
    original = model.objects
    model.objects = model.objects.using(MainRouter.admin_db)
    try:
        yield
    finally:
        model.objects = original

# Usage
with using_admin_db(TenantAPIKey):
    key = TenantAPIKey.objects.get(prefix=prefix)
```

---

### 4.3 User Role Fetching Duplicated in `HasPermissions`

**File:** `api/src/backend/api/rbac/permissions.py` — lines ~38–43, ~61

The chained `.using(MainRouter.admin_db)` query for fetching a user's role in a tenant is written twice in the same file:

```python
# Current — at lines 39-42
user_roles = (
    User.objects.using(MainRouter.admin_db)
    .get(id=request.user.id)
    .roles.using(MainRouter.admin_db)
    .filter(tenant_id=tenant_id)
)

# Also at line 61
role = user.roles.using(MainRouter.admin_db).filter(tenant_id=tenant_id).first()
```

**Recommended fix:** Move into a utility function called from both sites:

```python
def get_role_in_tenant(user: User, tenant_id: str) -> "Role | None":
    return (
        user.roles
        .using(MainRouter.admin_db)
        .filter(tenant_id=tenant_id)
        .first()
    )
```

---

### 4.4 Signal Handlers Duplicate `TenantAPIKey` Revocation Logic

**File:** `api/src/backend/api/signals.py` — lines ~52 and ~65

Two signal handlers both call `.update(revoked=True)` on `TenantAPIKey` objects, differing only in the filter:

```python
# On User pre_delete
TenantAPIKey.objects.filter(entity=instance).update(revoked=True)

# On Membership post_delete
TenantAPIKey.objects.filter(entity_id=instance.user_id, tenant_id=instance.tenant_id).update(revoked=True)
```

**Recommended fix:** Extract a helper and call from both signals:

```python
def _revoke_api_keys(**filters) -> None:
    TenantAPIKey.objects.filter(**filters).update(revoked=True)

@receiver(pre_delete, sender=User)
def revoke_user_api_keys(sender, instance, **kwargs):
    _revoke_api_keys(entity=instance)

@receiver(post_delete, sender=Membership)
def revoke_membership_api_keys(sender, instance, **kwargs):
    _revoke_api_keys(entity_id=instance.user_id, tenant_id=instance.tenant_id)
```

---

## 5. Configuration & Settings

### 5.1 S3 Output Settings Use Repetitive Flat Namespace

**File:** `api/src/backend/config/django/base.py` — lines ~285–296

Five related S3 settings are declared as flat module-level variables sharing the same `DJANGO_OUTPUT_S3_AWS_` prefix:

```python
# Current
DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET    = env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", "")
DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID    = env.str("DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID", "")
DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY = env.str("DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY", "")
DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN    = env.str("DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN", "")
DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION   = env.str("DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION", "")
```

**Recommended fix:** Group into a single dict:

```python
OUTPUT_S3 = {
    "bucket":            env.str("DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET", ""),
    "access_key_id":     env.str("DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID", ""),
    "secret_access_key": env.str("DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY", ""),
    "session_token":     env.str("DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN", ""),
    "region":            env.str("DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION", ""),
}
```

Access sites change from `settings.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET` to `settings.OUTPUT_S3["bucket"]`. Passing the whole config to S3 utility functions also becomes trivial.

---

### 5.2 Task Recovery Feature Flags as Three Separate Settings

**File:** `api/src/backend/config/django/base.py` — lines ~318–324

Three booleans that control the same feature area are separate top-level settings:

```python
# Current
TASK_RECOVERY_ENABLED            = env.bool("DJANGO_TASK_RECOVERY_ENABLED", False)
TASK_RECOVERY_SUMMARIES_ENABLED  = env.bool("DJANGO_TASK_RECOVERY_SUMMARIES_ENABLED", True)
TASK_RECOVERY_DELETIONS_ENABLED  = env.bool("DJANGO_TASK_RECOVERY_DELETIONS_ENABLED", True)
```

**Recommended fix:** Nest under one key:

```python
TASK_RECOVERY = {
    "enabled":            env.bool("DJANGO_TASK_RECOVERY_ENABLED", False),
    "summaries_enabled":  env.bool("DJANGO_TASK_RECOVERY_SUMMARIES_ENABLED", True),
    "deletions_enabled":  env.bool("DJANGO_TASK_RECOVERY_DELETIONS_ENABLED", True),
}
```

---

## Summary

| # | Finding | File(s) | Type | Estimated Line Reduction |
|---|---------|---------|------|--------------------------|
| 1.1 | 11 identical enum field classes | `db_utils.py` | Redundancy | ~120 → 14 |
| 1.2 | Fernet decrypt/encrypt duplicated 4× | `models.py` | Redundancy | ~80 |
| 1.3 | RLS constraint block copied ~30× | `models.py` | Redundancy | ~90 |
| 1.4 | N+1 loop in `add_resources()` | `models.py` | Performance | N→2 queries |
| 1.5 | Pointless `get_queryset()` override | `models.py` | Dead code | 3 lines |
| 1.6 | Email normalization in 2 `save()` methods | `models.py` | Redundancy | ~8 |
| 1.7 | Hardcoded `PERMISSION_FIELDS` list | `models.py` | Fragility | Maintenance |
| 1.8 | String concat loop in SQL generation | `rls.py` | Inefficiency | Readability |
| 1.9 | Possible SQL syntax error in `drop_sql_query` | `rls.py` | Bug risk | — |
| 1.10 | Suppressed unused `**hints` params | `db_router.py` | Code smell | — |
| 2.1 | `get_serializer_class()` copied 6+ times | `views.py` | Redundancy | ~30 |
| 2.2 | `set_required_permissions()` copied per ViewSet | `views.py` | Redundancy | ~25 |
| 2.3 | 5 identical report-serving actions | `views.py` | Redundancy | ~125 |
| 2.4 | 3 identical `ResourceIdentifierSerializer` classes | `serializers.py` | Redundancy | ~50 |
| 2.5 | Enum choice serializer fields copied ~8× | `serializers.py` | Redundancy | ~40 |
| 2.6 | Through-model creation repeated in 4 serializers | `serializers.py` | Redundancy | ~60 |
| 2.7 | RBAC visibility filter repeated in 3 ViewSets | `views.py` | Redundancy | ~20 |
| 3.1 | ~30 one-line task wrappers | `tasks.py` | Redundancy | ~300 |
| 3.2 | `visibility_timeout` set 3× | `celery.py` | Redundancy | ~5 |
| 3.3 | Implicit task annotation groups | `celery.py` | Maintainability | — |
| 3.4 | Non-reusable chord exception handler | `tasks.py` | Pattern gap | — |
| 4.1 | `__init__` body copied in 5 exception classes | `exceptions.py` | Redundancy | ~110 |
| 4.2 | Admin DB context repeated 3× | `authentication.py` | Redundancy | ~20 |
| 4.3 | User role fetch duplicated | `permissions.py` | Redundancy | ~8 |
| 4.4 | API key revocation logic duplicated | `signals.py` | Redundancy | ~5 |
| 5.1 | S3 settings as flat variables | `base.py` | Maintainability | — |
| 5.2 | Task recovery flags as 3 separate settings | `base.py` | Maintainability | — |

**Estimated total reduction:** 1,000–1,200 lines of application code with no functional change, and several performance improvements (N+1 queries, connection handling) with measurable runtime impact.
