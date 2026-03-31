# Project CyberLab
> Technical Reference Document / README.md

CyberLab is a Flask-based local cyber range orchestrator. It provisions intentionally vulnerable training targets as Docker containers, enforces role/team governance, tracks learner progress, and exposes instructor/admin controls for operational management.

This document is a code-aligned technical reference for deployment, runtime behavior, data model internals, route contracts, and troubleshooting.

## 1. System Overview

### 1.1 Runtime components

- Application runtime: Flask (`app.py`)
- WebSocket terminal transport: Flask-Sock
- Container orchestration: Docker SDK (`utils/docker_manager.py`)
- Persistence: SQLite (`database.db`)
- Background jobs: APScheduler (in-process)
- Presentation: Jinja templates (`templates/`) + static CSS (`static/style.css`)

### 1.2 Primary capabilities

- Multi-user authentication and role-based controls
- Dynamic vulnerable lab lifecycle (start/stop/reset/destroy)
- Per-user Docker bridge network isolation
- Checkpoint snapshot save/restore with retention policy
- Catalog-based unlock controls (score + prerequisites)
- Team invitations, team learning path controls, announcements
- Event audit timeline with export
- Password management:
  - Self-service password update (authenticated)
  - Forgot-password request + admin approval workflow
- Content pack import/export for catalog/flags mappings
- Browser web terminal for non-web labs

## 2. Repository Topology

- `app.py`: Flask app, DB bootstrap/migrations, route handlers, scheduler jobs
- `utils/docker_manager.py`: lab runtime config and Docker lifecycle helpers
- `templates/`: server-rendered UI pages
- `static/style.css`: shared UI stylesheet
- `content-packs/lightweight-localhost-labs.json`: default content pack
- `Dockerfile`: container image for CyberLab platform process
- `docker-compose.yml`: host-network deployment for platform container
- `database.db`: runtime SQLite database

Companion docs exist in folder-level READMEs:

- `utils/README.md`
- `templates/README.md`
- `static/README.md`
- `content-packs/README.md`

## 3. Dependency and Platform Requirements

### 3.1 Host requirements

- Linux (recommended for compose host networking mode)
- Python 3.10+
- Docker Engine running and reachable by current user

### 3.2 Python dependencies

From `requirements.txt`:

- `Flask==3.0.3`
- `flask-sock>=0.7.0`
- `docker>=7.1.0`
- `Werkzeug==3.0.1`
- `APScheduler>=3.11.0`
- `requests>=2.31.0`
- `python-dateutil>=2.9.0`

## 4. Execution Models

### 4.1 Native Python execution

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Application listens on `0.0.0.0:5000`.

### 4.2 Dockerized platform execution

```bash
docker compose up --build -d
```

Compose design notes:

- `network_mode: host` is used to preserve localhost semantics used by readiness checks
- `/var/run/docker.sock` is mounted so platform container can control host Docker
- `database.db` and `content-packs/` are mounted for persistence

Stop:

```bash
docker compose down
```

## 5. Security and Trust Boundaries

### 5.1 Intentional risk profile

CyberLab launches intentionally vulnerable targets. Treat the host as a lab environment.

### 5.2 Secret and session notes

- Flask secret key is currently source-defined in `app.py`
- Admin bootstrap is controlled by `CYBERLAB_BOOTSTRAP_KEY`
- Do not expose directly to untrusted networks without TLS/reverse-proxy hardening and strict segmentation

### 5.3 Password workflows

- Self-service update route requires current password verification
- Forgot-password requests require explicit admin action before user credential is changed

## 6. Role and Access Model

### 6.1 Roles

- `student`
- `instructor`
- `admin`

### 6.2 Enforcement

- Decorator: `@require_roles(...)` on privileged endpoints
- Role stored in `users.role`, mirrored into session at login

### 6.3 Bootstrap

1. Start app with `CYBERLAB_BOOTSTRAP_KEY`
2. Open `/admin/bootstrap`
3. Promote existing user to `admin`

## 7. Lab Runtime Model

### 7.1 Source of truth

`LAB_CONFIGS` in `utils/docker_manager.py` defines runtime lab set, images, ports, and optional behavior overrides.

### 7.2 Active lab set

Current configured slugs:

- `juice-shop`
- `dvwa`
- `bwapp`
- `webgoat`
- `mutillidae`
- `railsgoat`
- `dvga`
- `vampi`
- `juice-shop-ctf`
- `kubehunter`
- `redis`
- `ftp`
- `ssh`

### 7.3 Access modes

- Default `web`
- `cli` (for example `kubehunter`)
- `service` (for example `redis`, `ftp`, `ssh`)

UI behavior is mode-aware:

- Web labs get `access_url` and readiness probes
- Non-web labs surface protocol/tooling guidance and web terminal options

### 7.4 Lab-specific runtime overrides

- `railsgoat`: command executes migrate + seed + server
- `dvga`: environment includes `WEB_HOST=0.0.0.0`
- `kubehunter`: command keeps container alive, with entrypoint override and interactive flags

### 7.5 Container lifecycle functions

In `utils/docker_manager.py`:

- `start_container(port, user_id, lab_type)`
- `stop_container(container_id)`
- `resume_container(container_id)`
- `remove_container(container_id)`
- `get_container_status(container_id)`

## 8. Networking Semantics

### 8.1 Per-user network

Network naming convention:

- `cyberlab-user-<user_id>`

Lifecycle:

- `ensure_lab_network(user_id)` creates/reuses bridge network
- User-owned containers are attached on startup
- `prune_user_network_if_unused(user_id)` removes network after last user container is gone

### 8.2 Port allocation

- App allocates host ports dynamically via DB + socket availability checks
- Runtime collisions are mitigated by iterative search

## 9. Application Request Lifecycle

### 9.1 Login and session establishment

- User credential verification against `users.password_hash`
- Session keys set: `user_id`, `username`, `role`
- Audit event `user_login` recorded

### 9.2 Dashboard composition

`/dashboard` resolves:

- User containers + live Docker status reconciliation
- Catalog visibility based on role/team learning paths
- Unlock state (score and prerequisites)
- Team invites and announcements
- Global and team scoreboards
- Snapshot list and retention settings

### 9.3 Lab launch path

`/start_lab` sequence (high-level):

1. Validate auth and launch eligibility
2. Select available host port
3. Resolve selected lab config
4. Start Docker container via `start_container`
5. Persist container record
6. Record event

### 9.4 Lab operation path

- `/stop_lab` => stop + DB status update
- `/reset_lab` => remove + recreate on same host port
- `/destroy_lab` => remove + DB deletion

### 9.5 Web terminal path

- HTTP page: `/terminal`
- WebSocket stream: `/ws/terminal/<container_id>`
- Ownership checks ensure user can only access own container sessions

## 10. Authentication and Password Management

### 10.1 Routes

- `GET|POST /login`
- `GET|POST /forgot_password`
- `POST /account/password`
- `POST /admin/password_reset/<request_id>/<action>`

### 10.2 Forgot-password state machine

`password_reset_requests.status`:

- `pending`
- `approved`
- `rejected`

On approval:

- `users.password_hash` updated from stored requested hash
- request row marked resolved with admin metadata

## 11. Team and Organization Model

### 11.1 Entities

- Organizations (`organizations`)
- Team quotas (`organization_budgets`, `teams.max_active_labs`)
- Memberships (`team_memberships`)
- Invites (`team_invites`)
- Team learning paths (`team_learning_paths`)

### 11.2 Invite flow

1. Instructor/admin creates invite by username
2. Invite is stored as pending
3. Student sees pending invite card on dashboard
4. Student accepts via `/invite/<invite_code>/accept`
5. Membership row is created and invite marked accepted

## 12. Catalog and Progression Controls

### 12.1 Catalog source

- DB table: `lab_catalog`
- Runtime filtering: role + team learning path constraints

### 12.2 Unlock controls

Per-lab constraints:

- `required_score`
- `prerequisite_labs_json`

Decision function:

- `evaluate_lab_unlock(...)`

### 12.3 Completion tracking

- Manual and mapped completion recorded in `user_lab_completions`
- Flag mappings (`flag_lab_mappings`) can drive exact completion attribution

## 13. Instructor and Admin Console

Primary route:

- `/instructor/activity`

Features:

- Active instance view + force actions
- Event timeline filters and export (JSON/CSV)
- Announcement broadcast
- Team creation/invite/path mapping
- Catalog rule management
- Flag-to-lab mapping management
- Admin-only password reset approvals

## 14. Webhook and Anti-Cheat Guardrails

Webhook endpoint:

- `POST|PUT /webhook/<user_id>`

Guardrails implemented:

- Replay-key dedupe (`webhook_replay_guard`)
- Event-rate throttling over rolling window
- Event logging for accepted/rejected webhook activity

## 15. Snapshot System

### 15.1 User actions

- Save: `/checkpoint/save`
- Restore: `/checkpoint/restore`
- Retention settings: `/checkpoint/settings`

### 15.2 Retention cleanup

- Background cleanup respects per-user retention count from `user_settings`
- Snapshot metadata stored in `lab_snapshots`

## 16. Port Cleaner and Lifecycle Hygiene

Routes:

- `/port_cleaner`
- `/port_cleaner/action`
- `/port_cleaner/clean_all`

Capabilities:

- Show DB-tracked and user-owned containers
- Compare DB status versus live Docker status
- Perform stop/resume/destroy actions
- Bulk cleanup of user-managed containers

## 17. Data Model: Table-Level Reference

Tables initialized in `init_db()`:

- `users`
  - `id`, `username`, `password_hash`, `score`, `role`, `organization_id`
- `containers`
  - `id`, `user_id`, `container_id`, `port`, `status`, `lab_type`, `network_name`
- `flags`
  - `id`, `flag_value`, `points`
- `solved_flags`
  - composite key: `(user_id, flag_id)`
- `organizations`
  - `id`, `name`, `created_at`
- `organization_budgets`
  - `organization_id`, `max_active_labs`
- `teams`
  - `id`, `organization_id`, `name`, `max_active_labs`
- `team_memberships`
  - composite key: `(user_id, team_id)`, `role`
- `team_invites`
  - `id`, `team_id`, `invitee_username`, `invite_code`, `status`, `created_by`, `created_at`
- `password_reset_requests`
  - `id`, `user_id`, `requested_password_hash`, `status`, `requested_at`, `resolved_at`, `resolved_by`, `admin_note`
- `team_learning_paths`
  - composite key: `(team_id, learning_path)`
- `announcements`
  - `id`, `organization_id`, `team_id`, `message`, `created_by`, `created_at`
- `event_log`
  - `id`, `created_at`, `event_type`, `user_id`, `target_user_id`, `source_ip`, `details_json`
- `webhook_replay_guard`
  - `id`, `user_id`, `replay_key`, `created_at`
- `lab_catalog`
  - `id`, `slug`, `name`, `description`, `image`, `internal_port`, `entry_path`, `mem_limit`, `needs_volume`, `volume_path`, `version`, `tags_json`, `difficulty`, `learning_path`, `required_score`, `prerequisite_labs_json`, `is_active`, `updated_at`
- `user_lab_completions`
  - composite key: `(user_id, lab_slug)`, `completion_source`, `completed_at`
- `flag_lab_mappings`
  - composite key: `(flag_id, lab_slug)`
- `lab_snapshots`
  - `id`, `user_id`, `container_record_id`, `snapshot_name`, `image_tag`, `created_at`
- `user_settings`
  - `user_id`, `snapshot_retention_count`

## 18. Scheduler and Background Operations

Scheduler starts in `__main__` with:

- `cleanup_idle_containers` every 10 minutes
- `cleanup_snapshot_retention` every 30 minutes

Operational implication:

- Jobs execute only while the Flask process is running

## 19. API/Route Reference (Current)

### 19.1 Auth and account

- `GET /`
- `GET|POST /register`
- `GET|POST /login`
- `GET|POST /forgot_password`
- `POST /account/password`
- `GET|POST /admin/bootstrap`
- `GET /logout`

### 19.2 Student operations

- `GET /dashboard`
- `POST|PUT /webhook/<user_id>`
- `POST /start_lab`
- `POST /stop_lab`
- `POST /reset_lab`
- `POST /destroy_lab`
- `POST /checkpoint/save`
- `POST /checkpoint/restore`
- `POST /checkpoint/settings`
- `GET /port_cleaner`
- `POST /port_cleaner/clean_all`
- `POST /port_cleaner/action`
- `POST /submit_flag`
- `GET /proxy_guide`
- `GET /terminal`
- `GET /catalog`
- `POST /invite/<invite_code>/accept`

### 19.3 Content packs

- `GET /content_pack/export`
- `GET|POST /content_pack/import`

### 19.4 Instructor/Admin operations

- `GET /instructor/activity`
- `POST /instructor/announce`
- `POST /instructor/lab_action`
- `POST /instructor/invite`
- `POST /instructor/team_create`
- `POST /instructor/team_path`
- `POST /instructor/catalog_rule`
- `POST /instructor/flag_lab_mapping`
- `POST /admin/password_reset/<request_id>/<action>` (admin-only)

### 19.5 WebSocket endpoint

- `WS /ws/terminal/<container_id>`

## 20. Troubleshooting Playbook

### 20.1 Port bind conflicts on platform startup

```bash
fuser -k 5000/tcp || true
python app.py
```

### 20.2 Lab unreachable or reset errors

- Recreate lab instance after config changes
- Check if lab is web/service/cli mode
- Inspect container logs directly when UI shows running but endpoint fails

### 20.3 Docker control failures

- Verify daemon state
- Verify user/group access to Docker socket
- For compose deployment, verify `/var/run/docker.sock` mount exists

### 20.4 RailsGoat errors around missing tables

Expected behavior is migration+seed on startup. If stale instance predates fix:

- Destroy and recreate RailsGoat instance

### 20.5 DVGA connection reset

DVGA requires `WEB_HOST=0.0.0.0` (already configured). For stale instances:

- Destroy and recreate DVGA instance

## 21. Observability and Auditing

Audit data is persisted in `event_log` for key actions:

- Auth events
- Lab lifecycle events
- Instructor/admin actions
- Team invite and path mapping operations
- Password reset request and approval/rejection events

Instructor console provides filtered timeline and export options.

## 22. Operational Best Practices

- Keep host Docker updated
- Keep lab runtime isolated from production environments
- Rotate and externalize secret material for non-local deployments
- Restrict admin role assignments and bootstrap key distribution
- Periodically review event log and pending admin requests

## 23. End-to-End Runbooks (Detailed)

This section provides full procedural flows for common operations from a clean machine to active multi-user training.

### 23.1 End-to-End: First-Time Native Setup

1. Clone the repository and enter project directory.
2. Ensure Docker daemon is running.
3. Create virtual environment.
4. Activate virtual environment.
5. Install dependencies.
6. Start application.
7. Open platform URL.

Commands:

```bash
git clone <repo-url>
cd Cyberlab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Browser:

```text
http://127.0.0.1:5000
```

Expected outcomes:

- SQLite schema is auto-created/migrated by init_db.
- Seed flag is inserted if flags table is empty.
- Default organization and budget rows exist.
- Scheduler jobs start in-process.

### 23.2 End-to-End: First Admin Bootstrap

1. Register a normal user account (future admin).
2. Stop app process if already running.
3. Restart with bootstrap key environment variable.
4. Visit admin bootstrap endpoint.
5. Submit target username and bootstrap key.
6. Verify user role changed to admin.

Command example:

```bash
CYBERLAB_BOOTSTRAP_KEY="replace-with-secure-key" python app.py
```

Bootstrap URL:

```text
http://127.0.0.1:5000/admin/bootstrap
```

Validation:

- Admin can access Instructor console.
- Session role resolves as admin after login.

### 23.3 End-to-End: Team Provisioning and Invite Acceptance

Instructor/admin side:

1. Login as instructor or admin.
2. Navigate to Instructor Console.
3. Create team with name and max active labs.
4. Create invite for student username.
5. Optionally assign learning path to team.

Student side:

1. Login with invited username.
2. Open Dashboard.
3. Locate Pending Team Invites card.
4. Accept invite.
5. Verify team-based announcements and learning path filtering apply.

Validation points:

- team_memberships row created on acceptance.
- team_invites status becomes accepted.
- Team leaderboard includes the student score contribution.

### 23.4 End-to-End: Student Lab Lifecycle

1. Login as student.
2. Open Dashboard.
3. Select lab in launch grid.
4. Start lab.
5. Wait for running/readiness state.
6. Access lab via Open link (web labs) or Terminal/guide (non-web labs).
7. Perform exercises.
8. Stop or reset as needed.
9. Destroy when finished to free resources.

Operational notes:

- Port is dynamically allocated and stored in containers table.
- Container is attached to per-user bridge network.
- UI status is reconciled with live Docker status.

### 23.5 End-to-End: Snapshot Save and Restore

1. Start a lab and reach desired checkpoint state.
2. Click Save Checkpoint.
3. Confirm snapshot row appears in dashboard snapshot controls.
4. Continue experimentation.
5. Use Restore to revert to saved snapshot state.
6. Optionally set retention count in Snapshot Retention card.

Validation:

- lab_snapshots row exists for user.
- Snapshot image tag is created and referenced.
- Restore replaces running instance image/state according to workflow.

### 23.6 End-to-End: Forgot Password with Admin Approval

User request flow:

1. Open login page.
2. Click Forgot password.
3. Enter username, new password, confirmation.
4. Submit request.

Admin approval flow:

1. Login as admin.
2. Open Instructor Console.
3. Review Password Reset Requests panel.
4. Approve or reject request (optional note).

Post-approval:

1. User returns to login.
2. User authenticates with approved password.

Validation:

- password_reset_requests transitions pending to approved or rejected.
- On approval, users.password_hash is updated.
- Event log entries are recorded for request and decision.

### 23.7 End-to-End: Dockerized Platform Deployment

1. Ensure Linux host with Docker Engine.
2. Verify docker compose is available.
3. Build and launch compose stack.
4. Open application URL.
5. Verify platform can launch lab containers.
6. Stop stack when done.

Commands:

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f cyberlab
```

Stop:

```bash
docker compose down
```

Critical deployment details:

- Host networking is required by current localhost-oriented checks.
- Docker socket mount is required for lab orchestration from platform container.
- database.db and content-packs are bind-mounted for persistence.

### 23.8 End-to-End: Content Pack Export, Edit, Re-Import

1. Login as instructor/admin.
2. Export content pack from UI route.
3. Modify labs/flags/mappings JSON offline.
4. Import modified JSON through content pack import form.
5. Verify catalog updates.
6. Verify launch eligibility and lab display changes.

Validation:

- lab_catalog updated via slug upsert behavior.
- flags upserted by flag_value.
- flag_lab_mappings inserted for valid references.

### 23.9 End-to-End: Instructor Incident Response for Stuck Labs

1. Open Instructor Console.
2. Review active labs and monitor metrics.
3. If student lab is unhealthy, execute one of:
  - force_stop
  - force_reset
  - force_destroy
4. Confirm student can relaunch clean instance.
5. Review event timeline to document action.

Validation:

- Target lab row status or existence reflects action.
- Event log contains instructor action record.

### 23.10 End-to-End: Operational Health Checklist

Run this checklist before live training sessions:

1. Confirm Docker daemon running.
2. Confirm app reachable on port 5000.
3. Confirm at least one web lab launches and opens.
4. Confirm one non-web lab terminal session works.
5. Confirm instructor console loads.
6. Confirm team invite acceptance path works.
7. Confirm forgot-password request and admin approval path works.
8. Confirm snapshot save and restore work.
9. Confirm content pack export/import accessible.
10. Confirm event export works.

Optional quick sanity commands:

```bash
python -m py_compile app.py utils/docker_manager.py
docker ps
docker network ls | grep cyberlab-user-
```
