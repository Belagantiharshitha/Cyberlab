# utils

Utility layer for Docker/lab runtime integration.

## Files

- `docker_manager.py`: 
  - Lab runtime configuration (`LAB_CONFIGS`)
  - Docker client initialization
  - Lab network create/prune helpers
  - Container start/stop/resume/remove/status operations
  - Lab-specific startup behavior (for example RailsGoat migrate+seed, DVGA host bind env)

## Why this folder exists

This folder isolates container orchestration and lab runtime behavior from Flask route logic in `app.py`.
