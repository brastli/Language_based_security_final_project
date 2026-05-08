"""
Case 059: minimal reproduction of BaseModelAdmin.get_empty_value_display (django-11149).
Trims django.contrib.admin bulk; keeps the mark_safe sink semantics for Bandit / repair.
"""

# ---------------------------------------------------------------------------
# 上游对照 / Upstream reference
# ---------------------------------------------------------------------------
# - Issue: https://code.djangoproject.com/ticket/11149
# - Upstream file: django/contrib/admin/options.py
#   Method: BaseModelAdmin.get_empty_value_display
# - Full snapshot in this repo:
#   dataset/django_vulnerabilities/django__django-11149__django_contrib_admin_options.py
#   (the method is around lines 378–385 in that file.)
# - This file is intentionally short: only the sink + minimal stubs; line count != upstream.
# ---------------------------------------------------------------------------

try:
    from django.utils.safestring import mark_safe
except Exception:
    class SafeString(str):
        """Fallback used only when Django is unavailable in test environments."""

    def mark_safe(value):
        return SafeString(str(value))


class AdminSiteStub:
    def __init__(self, empty_value_display="-"):
        self.empty_value_display = empty_value_display


class BaseModelAdmin:
    def __init__(self, empty_value_display=None, admin_site=None):
        if empty_value_display is not None:
            self.empty_value_display = empty_value_display
        self.admin_site = admin_site or AdminSiteStub()

    def get_empty_value_display(self):
        """
        Return the empty_value_display set on ModelAdmin or AdminSite.
        VULNERABLE: untrusted HTML is marked as safe and bypasses escaping.
        """
        try:
            return mark_safe(self.empty_value_display)
        except AttributeError:
            return mark_safe(self.admin_site.empty_value_display)


def get_empty_value_display(value):
    """
    Function wrapper for test tools that prefer function-level imports.
    """
    admin = BaseModelAdmin(empty_value_display=value, admin_site=AdminSiteStub("-"))
    return admin.get_empty_value_display()
