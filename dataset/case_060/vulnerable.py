"""
Case 060: minimal reproduction of django.contrib.admin.helpers (django-12343).
Keeps the vulnerable mark_safe usage in admin error rendering.
"""

# ---------------------------------------------------------------------------
# 上游对照 / Upstream reference
# ---------------------------------------------------------------------------
# - Issue: https://code.djangoproject.com/ticket/12343
# - Upstream file: django/contrib/admin/helpers.py
# - Full snapshot in this repo:
#   dataset/django_vulnerabilities/django__django-12343__django_contrib_admin_helpers.py
# - This file is intentionally short to keep dataset cases runnable without a full
#   Django project while preserving the vulnerability sink semantics.
# ---------------------------------------------------------------------------

try:
    from django.utils.safestring import mark_safe
except Exception:
    class SafeString(str):
        """Fallback used only when Django is unavailable in test environments."""

    def mark_safe(value):
        return SafeString(str(value))


class MockErrors:
    def __init__(self, raw_html):
        self.raw_html = raw_html

    def as_ul(self):
        return f"<ul class='errorlist'><li>{self.raw_html}</li></ul>"


class MockBoundField:
    def __init__(self, raw_html):
        self.errors = MockErrors(raw_html)


class MockForm:
    def __init__(self, field_to_error):
        self._field_to_error = dict(field_to_error)

    def __getitem__(self, key):
        return MockBoundField(self._field_to_error[key])


class Fieldline:
    def __init__(self, form, field, readonly_fields=None, model_admin=None):
        self.form = form
        if not hasattr(field, "__iter__") or isinstance(field, str):
            self.fields = [field]
        else:
            self.fields = field
        self.model_admin = model_admin
        if readonly_fields is None:
            readonly_fields = ()
        self.readonly_fields = readonly_fields

    def errors(self):
        # VULNERABLE: mirrors upstream sink from django admin helpers.
        return mark_safe(
            "\n".join(
                self.form[f].errors.as_ul()
                for f in self.fields
                if f not in self.readonly_fields
            ).strip("\n")
        )


class AdminField:
    def __init__(self, form, field):
        self.field = form[field]

    def errors(self):
        # VULNERABLE: second sink from upstream helpers.py.
        return mark_safe(self.field.errors.as_ul())


def get_errors_display(form, fields, readonly_fields=None):
    if readonly_fields is None:
        readonly_fields = ()
    return Fieldline(form, fields, readonly_fields=readonly_fields).errors()


def get_admin_field_errors_display(form, field):
    return AdminField(form, field).errors()
