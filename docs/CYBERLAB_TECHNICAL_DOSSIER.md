# CyberLab Technical Dossier (Research-Grade)

## 1. Scope and Evidence Base

This document is a code-aligned technical analysis of the CyberLab platform implementation as present in this workspace.

Primary artifacts analyzed:
- [app.py](app.py)
- [utils/docker_manager.py](utils/docker_manager.py)
- [requirements.txt](requirements.txt)
- [Dockerfile](Dockerfile)
- [docker-compose.yml](docker-compose.yml)
- [templates/base.html](templates/base.html)
- [templates/dashboard.html](templates/dashboard.html)
- [templates/instructor_activity.html](templates/instructor_activity.html)
- [templates/terminal.html](templates/terminal.html)
- [templates/proxy_guide.html](templates/proxy_guide.html)
- [static/style.css](static/style.css)
- [content-packs/lightweight-localhost-labs.json](content-packs/lightweight-localhost-labs.json)
- [README.md](README.md)

Analysis date context: 2026-04-01.

## 2. Quantitative Snapshot

Codebase and artifact metrics:
- Backend service file size: 2,466 lines in [app.py](app.py)
- Container orchestration module size: 366 lines in [utils/docker_manager.py](utils/docker_manager.py)
- Shared stylesheet size: 345 lines in [static/style.css](static/style.css)
- HTML template count: 11 files in [templates](templates)
- Default content pack size: 257 lines in [content-packs/lightweight-localhost-labs.json](content-packs/lightweight-localhost-labs.json)

Surface and model metrics:
- HTTP route handlers: 35 in [app.py](app.py)
- WebSocket route handlers: 1 in [app.py](app.py)
- Persistent SQLite tables initialized/migrated in code: 19 in [app.py](app.py)
- Configured lab runtime profiles in LAB_CONFIGS: 13 in [utils/docker_manager.py](utils/docker_manager.py)
- Default content-pack lab records: 13 in [content-packs/lightweight-localhost-labs.json](content-packs/lightweight-localhost-labs.json)
- Static event emission callsites: 37 in [app.py](app.py)

Resource envelope from configured labs:
- Sum of per-container memory limits across all 13 configured labs: approximately 7.536 GiB theoretical upper bound if one instance of each lab is launched concurrently.

## 3. High-Level System Architecture

CyberLab is a monolithic Flask application that orchestrates intentionally vulnerable Dockerized labs, with role-aware governance and in-band operations controls.

Core subsystems:
- Web/API and control plane: Flask in [app.py](app.py)
- Interactive terminal transport: Flask-Sock WebSocket endpoint in [app.py](app.py)
- Runtime workload manager: Docker SDK logic in [utils/docker_manager.py](utils/docker_manager.py)
- Persistence: SQLite database file [database.db](database.db)
- Periodic maintenance plane: APScheduler jobs in [app.py](app.py)
- UI rendering: Jinja templates in [templates](templates)
- Styling/theme: [static/style.css](static/style.css)
- Content portability: JSON import/export via [content-packs/lightweight-localhost-labs.json](content-packs/lightweight-localhost-labs.json)

Execution model:
- Single process app server with in-process scheduler.
- Direct Docker Engine control via local daemon or mounted docker.sock.
- Session-based auth maintained by Flask session cookie.

## 4. Runtime and Deployment Topology

### 4.1 Python runtime dependencies

Declared in [requirements.txt](requirements.txt):
- Flask 3.0.3
- flask-sock >= 0.7.0
- docker >= 7.1.0
- Werkzeug 3.0.1
- APScheduler >= 3.11.0
- requests >= 2.31.0
- python-dateutil >= 2.9.0

### 4.2 Containerized deployment

Platform image defined by [Dockerfile](Dockerfile):
- Base image: python:3.12-slim
- Working directory: /app
- Exposed port: 5000
- Entrypoint command: python app.py

Orchestration in [docker-compose.yml](docker-compose.yml):
- Service: cyberlab
- network_mode: host
- docker.sock bind-mounted for host Docker control
- database and content-pack bind mounts for persistence
- bootstrap key injected via environment variable

Operational implication of host networking:
- Localhost semantics are preserved for readiness probes.
- Isolation boundaries are host-level, not Docker bridge-level, for the platform service itself.

## 5. Configuration and Lab Runtime Model

### 5.1 LAB_CONFIGS structure

Lab definitions in [utils/docker_manager.py](utils/docker_manager.py) encode:
- slug
- user-facing name/description
- image reference
- container internal port mapping key
- entry path
- memory limit
- volume requirements
- optional environment overrides
- optional command overrides
- optional entrypoint/interactive toggles
- access mode hints for UI behavior

### 5.2 Supported lab profiles (13)

Web-centric:
- juice-shop
- dvwa
- bwapp
- webgoat
- mutillidae
- railsgoat
- dvga
- vampi
- juice-shop-ctf

Service and CLI-centric:
- kubehunter (cli)
- redis (service)
- ftp (service)
- ssh (service)

Advanced launch behavior:
- railsgoat: migration + seed + server command override
- dvga: WEB_HOST environment override
- kubehunter: entrypoint override with interactive/TTY behavior
- bwapp: post-launch bootstrap initialization via install.php readiness loop

## 6. Data Model (SQLite) Deep Schema

Tables initialized in [app.py](app.py):

1. users
- id PK
- username unique
- password_hash
- score default 0
- role default student (migrated)
- organization_id (migrated)

2. containers
- id PK
- user_id FK -> users
- container_id
- port
- status
- lab_type default juice-shop
- network_name

3. flags
- id PK
- flag_value unique
- points

4. solved_flags
- user_id, flag_id composite PK

5. organizations
- id PK
- name unique
- created_at

6. organization_budgets
- organization_id PK/FK
- max_active_labs default 50

7. teams
- id PK
- organization_id FK
- name
- max_active_labs default 10
- unique (organization_id, name)

8. team_memberships
- user_id, team_id composite PK
- role default student

9. team_invites
- id PK
- team_id FK
- invitee_username
- invite_code unique
- status default pending
- created_by
- created_at

10. password_reset_requests
- id PK
- user_id FK
- requested_password_hash
- status default pending
- requested_at
- resolved_at
- resolved_by FK
- admin_note

11. team_learning_paths
- team_id, learning_path composite PK

12. announcements
- id PK
- organization_id FK
- team_id nullable FK
- message
- created_by FK
- created_at

13. event_log
- id PK
- created_at
- event_type
- user_id FK nullable
- target_user_id FK nullable
- source_ip nullable
- details_json

14. webhook_replay_guard
- id PK
- user_id FK
- replay_key unique
- created_at

15. lab_catalog
- id PK
- slug unique
- name/description/image
- internal_port/entry_path
- mem_limit
- needs_volume/volume_path
- version
- tags_json
- difficulty
- learning_path
- required_score
- prerequisite_labs_json
- is_active
- updated_at

16. user_lab_completions
- user_id, lab_slug composite PK
- completion_source
- completed_at

17. flag_lab_mappings
- flag_id, lab_slug composite PK

18. lab_snapshots
- id PK
- user_id FK
- container_record_id FK
- snapshot_name
- image_tag unique
- created_at

19. user_settings
- user_id PK/FK
- snapshot_retention_count default 5

Bootstrap and seed behavior:
- Ensures default organization id=1 and budget row.
- Backfills missing role/org for existing users.
- Seeds at least one starter flag if flags table empty.
- Seeds lab_catalog entries from LAB_CONFIGS using INSERT OR IGNORE.

## 7. Access Control and Trust Model

Role system in [app.py](app.py):
- Roles: student, instructor, admin
- Decorator-based gate: require_roles
- Session role caching with DB fallback

Privilege highlights:
- student: launch/manage own labs, submit flags, access dashboard/terminal/proxy guide
- instructor: activity console, team operations, broadcast, catalog rule updates, force lab actions, content-pack import/export
- admin: all instructor capabilities plus password reset approval/rejection and bootstrap-level control

Identity/session facts:
- Session keys include user_id, username, role.
- Route guards are mostly session-presence plus role checks.

## 8. HTTP and WebSocket Surface

### 8.1 Authentication/account routes
- /
- /register
- /login
- /logout
- /forgot_password
- /account/password
- /admin/bootstrap

### 8.2 Learner operations
- /dashboard
- /start_lab
- /stop_lab
- /reset_lab
- /destroy_lab
- /submit_flag
- /proxy_guide
- /terminal
- /catalog
- /invite/<invite_code>/accept

### 8.3 Checkpoint lifecycle
- /checkpoint/save
- /checkpoint/restore
- /checkpoint/settings

### 8.4 Port maintenance console
- /port_cleaner
- /port_cleaner/clean_all
- /port_cleaner/action

### 8.5 Instructor/admin governance
- /instructor/activity
- /instructor/announce
- /instructor/lab_action
- /instructor/invite
- /instructor/team_create
- /instructor/team_path
- /instructor/catalog_rule
- /instructor/flag_lab_mapping
- /admin/password_reset/<request_id>/<action>

### 8.6 Content pack lifecycle
- /content_pack/export
- /content_pack/import

### 8.7 Programmatic scoring webhook
- /webhook/<user_id>

### 8.8 WebSocket endpoint
- /ws/terminal/<container_id>

## 9. End-to-End Operational Flows

### 9.1 Registration and login
1. User submits username/password to /register.
2. Password is hashed (Werkzeug).
3. User row created with role student and default org.
4. Login verifies hash and establishes session.
5. user_login event emitted.

### 9.2 Lab launch flow
1. /start_lab receives selected lab slug.
2. Quota checks run:
- organization max_active_labs
- each team max_active_labs
3. Catalog and unlock checks run:
- lab exists in catalog
- required_score condition
- prerequisite completion condition
4. Port allocation scans from 3001 upward with DB-used and socket availability checks.
5. Docker manager ensures image, network, and optional volume.
6. Container starts with labels for ownership and managed-by metadata.
7. DB inserts containers row and event_log entry.

### 9.3 Runtime management flow
- stop_lab: stop container, status -> exited
- reset_lab: remove old container, reallocate/reuse port, start new container, update row
- destroy_lab: remove container, delete row, prune user network if now unused

### 9.4 Checkpoint flow
Save:
1. Resolve user-owned lab record.
2. Docker commit container into tagged image.
3. Insert lab_snapshots row.

Restore:
1. Validate snapshot ownership.
2. Remove current container.
3. Re-run container from snapshot image using original lab port and policy labels.
4. Update containers row.

Retention:
- Per-user retention in user_settings.
- Background job prunes stale snapshot images and DB rows.

### 9.5 Flag and scoring flow
Manual flag:
1. /submit_flag validates against flags table.
2. Deduplicates via solved_flags.
3. Increments user score.
4. Maps flag -> lab completion when explicit mapping exists.
5. Falls back to marking active labs completed if mapping absent.

Webhook solve:
1. /webhook/<user_id> accepts POST/PUT JSON.
2. Replay guard checks X-Event-ID or payload hash key.
3. Rate limit checks max 30 accepted events per 5 minutes per user.
4. Adds +10 score on acceptance.
5. Marks active labs completed.

### 9.6 Instructor supervision flow
- Instructor console aggregates:
- active lab map
- timeline filters/export (JSON/CSV)
- resource monitor (CPU/memory from Docker stats)
- stuck-student heuristic signals
- team, path, invite, announcement controls
- catalog unlock rule management
- flag-lab mapping management
- optional admin password reset queue

### 9.7 Terminal flow
1. /terminal resolves selected user-owned container.
2. Browser opens xterm.js frontend and WebSocket to /ws/terminal/<id>.
3. Server verifies ownership via containers row.
4. Each submitted command executes inside container via exec_run(shell=True).
5. Output is streamed back to browser terminal.

## 10. Networking, Isolation, and Port Strategy

Per-user bridge network naming:
- cyberlab-user-<user_id>

Isolation strategy:
- Every managed lab gets user_id and network_name labels.
- Network created lazily per user and pruned when user has no remaining labeled containers.

Port strategy:
- Sequential search from 3001 with max 1000 attempts.
- Candidate accepted only if not already tracked in DB and bind-check passes at socket level.
- Reset flow can advance port if original is no longer available.

## 11. Auditability and Telemetry Model

Event ledger:
- Central event_log table with type, actor, target, source IP, structured details JSON.

Observed static event categories include:
- identity lifecycle: user_registered, user_login, user_logout
- password lifecycle: password_reset_requested, password_changed_self_service, password_reset_approved, password_reset_rejected
- lab lifecycle: lab_started, lab_stopped, lab_reset, lab_destroyed
- forced operations: force_stop, force_reset, force_destroy
- checkpoint lifecycle: checkpoint_saved, checkpoint_restored, checkpoint_retention_updated
- scoring lifecycle: flag_submitted_accepted, flag_submitted_invalid, flag_duplicate_rejected, webhook_solve_accepted
- anti-cheat/reliability: webhook_duplicate_rejected, webhook_rate_limited
- operations hygiene: port_cleaner_stop, port_cleaner_resume, port_cleaner_destroy, port_cleaner_clean_all, port_cleaner_clean_all_partial
- content governance: content_pack_exported, content_pack_imported
- org/team governance: team_created, team_invite_created, team_invite_accepted, team_learning_path_added, team_learning_path_removed, announcement_broadcast, catalog_rule_updated, flag_lab_mapping_added, flag_lab_mapping_removed
- bootstrap lifecycle: admin_bootstrap_completed

Timeline export:
- JSON and CSV supported from instructor console.

## 12. UX and Template Contract Model

Primary views and their contracts:
- base layout and nav in [templates/base.html](templates/base.html)
- user operations dashboard in [templates/dashboard.html](templates/dashboard.html)
- instructor control plane in [templates/instructor_activity.html](templates/instructor_activity.html)
- lab-type-aware proxy guidance in [templates/proxy_guide.html](templates/proxy_guide.html)
- browser terminal with xterm.js in [templates/terminal.html](templates/terminal.html)

Notable UI behaviors:
- role-aware nav links and capability exposure
- multiple concurrent lab cards with per-instance actions
- integrated save/restore checkpoint controls
- launch-card locking UX driven by required score and prerequisites
- team invites and announcement feed on dashboard
- global and team leaderboard rendering

Styling profile:
- cyber/neon-themed glassmorphism palette in [static/style.css](static/style.css)
- typography imports for Inter and Fira Code
- responsive card/grid layout primitives

## 13. Content-Pack and Catalog Governance

Import/export format in [content-packs/lightweight-localhost-labs.json](content-packs/lightweight-localhost-labs.json):
- format_version
- generated_at
- labs array
- flags array
- flag_lab_mappings array

Current default pack state:
- 13 labs
- 0 flags
- 0 explicit flag_lab_mappings

Import semantics:
- Labs upsert by slug with full mutable fields including unlock rules.
- Flags upsert by flag_value with point updates.
- Mappings inserted as unique pairs where provided.

Export semantics:
- Exports full lab_catalog + flags + mappings as JSON attachment.

## 14. Reliability and Background Automation

APScheduler jobs in [app.py](app.py):
- cleanup_idle_containers every 10 minutes
- cleanup_snapshot_retention every 30 minutes

Idle container policy:
- Containers older than 2 hours (based on Docker StartedAt timestamp) are stopped and DB status is updated.

Snapshot retention policy:
- Keeps N latest snapshots per user, where N defaults to 5 and is user-configurable up to 50.
- Removes Docker images for stale snapshots where possible and purges DB records.

## 15. Security Posture and Risk Observations

Strengths:
- Password hashing via Werkzeug.
- Role-based route restrictions for privileged operations.
- Ownership checks for terminal and container operations.
- Replay protection and rate limiting for webhook scoring path.
- Per-user Docker network partitioning and metadata labeling.

High-impact risks to address for production-grade security:
- Hardcoded Flask secret key in source (session forgery risk if disclosed).
- No explicit CSRF protection on many state-changing POST routes.
- Terminal WebSocket executes arbitrary shell commands inside target containers by authenticated user design.
- Host docker.sock mount gives platform process broad host-level container control capability.
- Debugging and operational logs may expose sensitive runtime details if not sanitized.

Recommended hardening actions:
1. Move secret key to strong environment-managed secret and rotate existing key.
2. Add CSRF tokens globally for all mutating forms.
3. Constrain terminal command set or gate terminal by stricter role/policy where needed.
4. Restrict deployment to segmented lab networks behind reverse proxy and TLS.
5. Add comprehensive security headers and session cookie policy hardening.

## 16. Use Cases by Role (Detailed)

Student use cases:
1. Register and authenticate, then access personalized dashboard.
2. Launch one or multiple vulnerable labs subject to org/team quotas.
3. Manage lab lifecycle: stop, resume, reset, destroy.
4. Save and restore snapshots for iterative exploit workflows.
5. Submit manual flags for score progression.
6. Complete labs through webhook-integrated challenge events.
7. Use protocol-specific proxy/testing guidance.
8. Access browser terminal for non-web/service labs.
9. Accept team invites and participate in team score dynamics.
10. Self-service update account password.

Instructor use cases:
1. Observe active labs across organization and filtered teams.
2. Force stop/reset/destroy learner lab instances.
3. Track resource usage by container (CPU and memory).
4. Identify potentially stuck learners via behavior heuristics.
5. Broadcast announcements globally or per-team.
6. Create teams and set team-level active-lab quotas.
7. Generate invite codes for targeted users.
8. Assign/remove learning paths for team curriculum gating.
9. Update catalog unlock policy (score and prerequisites).
10. Maintain explicit mapping from flags to lab completion semantics.
11. Export event timelines for reporting and incident review.

Admin-specific use cases:
1. Bootstrap first admin identity using server-side bootstrap key.
2. Approve/reject queued forgot-password reset requests.
3. Operate all instructor capabilities with elevated governance role.

Platform operator use cases:
1. Deploy via Python runtime or docker-compose host-network profile.
2. Import and export content packs for curriculum portability.
3. Monitor and clean stale/orphaned containers with port cleaner console.
4. Tune per-user checkpoint retention policy and observe scheduler pruning.

## 17. Performance and Scalability Characteristics

Complexity highlights:
- Port allocation scan worst-case O(n + a), where n is tracked ports and a is attempt count up to 1000.
- Dashboard rendering scales with user container count plus joins for leaderboard and org/team aggregates.
- Instructor monitoring cost increases with number of running containers because stats calls are per-container.

Scalability constraints:
- SQLite write contention under high concurrent mutation workloads.
- Single-process scheduler and app runtime limit horizontal scaling without externalizing state and jobs.
- Docker daemon as central bottleneck for start/stop/exec and image operations.

Likely practical sweet spot:
- Small to medium training cohorts on a single host with controlled concurrent lab density.

## 18. Gaps and Future Engineering Opportunities

Potential next-phase enhancements:
1. Move to PostgreSQL with indexed event and container tables for stronger concurrent throughput.
2. Add asynchronous task queue for long-running Docker operations and image pulls.
3. Introduce signed, scoped API tokens for webhook identity instead of user-id URL trust model.
4. Add RBAC policy matrix externalization and audit policy engine.
5. Introduce observability stack (metrics/tracing/log pipelines) with SLOs.
6. Build automated integration tests for route authorization matrix and lifecycle flows.
7. Add immutable append-only audit export pipeline and tamper-evidence strategy.

## 19. Technical Conclusion

CyberLab is a feature-rich, monolithic cyber-range orchestration platform with substantial operational depth for a single-service architecture: multi-role governance, dynamic vulnerable lab lifecycle management, score/progression mechanics, curriculum gating, checkpointing, terminal access, and instructor telemetry all integrated in one codebase.

Its engineering profile is strongest for controlled, local or internally segmented training environments. With hardening around secrets, CSRF, session policy, and deployment boundaries, the same architecture can be elevated toward higher-assurance institutional deployments.