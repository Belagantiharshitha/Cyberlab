# templates

Jinja2 templates used by the CyberLab Flask UI.

## Main pages

- `base.html`: Shared layout, nav, flash messages
- `login.html`, `register.html`, `forgot_password.html`, `admin_bootstrap.html`: Auth and account pages
- `dashboard.html`: Student operations, invites, scoreboards, password update form
- `catalog.html`: Catalog browsing/launch eligibility
- `proxy_guide.html`: Lab-specific proxy/testing guidance
- `terminal.html`: Browser-based terminal for non-web labs
- `port_cleaner.html`: Container/port lifecycle maintenance
- `instructor_activity.html`: Instructor/admin control center (team ops, announcements, rules, reset approvals)
- `content_pack_import.html`: Content pack JSON import

## Notes

Templates are rendered directly from route handlers in `app.py`.
