#!/usr/bin/env python3
"""
bootstrap-app-folders.py — pre-create the per-app folder skeleton in Outline.

WHY THIS EXISTS
---------------
The outline-uploader action's folder-resolution uses POST /api/documents.search
to find each path segment, then POST /api/documents.create if not found. Under
matrix parallelism (e.g. FleetLink's 4 simultaneous scan shards) the search hits
a read replica that can lag the primary by hundreds of ms — every shard sees
"not found" for the shared `ci/` segment and creates its own duplicate.

This script runs SERIALLY during app onboarding and creates the entire folder
chain ahead of time:

    reports/ci/<short-code-lower>/<component>/latest    (placeholder doc)
    reports/ci/<short-code-lower>/<component>/history   (folder + placeholder)

After bootstrap, the runtime action only ever UPDATEs existing docs or creates
NEW children under existing parents — the race window is closed.

USAGE
-----
    # FleetLink — multi-component
    python3 scripts/bootstrap-app-folders.py \\
        --short-code NTH-AXT-FL-WA \\
        --components iam,fleet,telematics,audit \\
        --project-name "FleetLink"

    # Inquira — single-app
    python3 scripts/bootstrap-app-folders.py \\
        --short-code NTH-AXT-IQ-WA \\
        --components app \\
        --project-name "Inquira"

    # Infra scans
    python3 scripts/bootstrap-app-folders.py \\
        --short-code _infra \\
        --components base-image-daily,base-image-build,k8s-karpenter

Reads OUTLINE_API_KEY, OUTLINE_BASE_URL, OUTLINE_COLLECTION_ID from env.
Fully idempotent — running twice is a no-op (every folder lookup returns
"found existing"). Safe to wire into onboarding scripts.
"""

import argparse
import os
import sys

# Re-use the action's helpers so behaviour stays consistent.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

from upload import (  # noqa: E402 — sys.path adjustment above
    ensure_path,
    find_document_with_retry,
    create_document,
    slug,
)


def bootstrap_one_component(api_key, base_url, collection_id, short_code, component, project_name):
    """Create the folder chain + placeholder leaves for a single (app, component)."""
    sc_slug = slug(short_code)
    comp_slug = slug(component) or 'app'
    parent_path = f"reports/ci/{sc_slug}/{comp_slug}"

    print(f"\n[{sc_slug}/{comp_slug}] ensuring path: {parent_path}")
    parent_id = ensure_path(api_key, base_url, collection_id, parent_path)

    # Placeholder for `latest` so the runtime action UPDATEs (instead of CREATEs)
    # on the very first scan. The placeholder body is overwritten by the first
    # real scan; until then, operators see a clear "waiting for first scan" note.
    latest_id = find_document_with_retry(api_key, base_url, collection_id, "latest", parent_id)
    if latest_id:
        print(f"  ✓ latest doc already exists (id={latest_id})")
    else:
        print(f"  + creating 'latest' placeholder")
        proj = project_name or sc_slug.upper()
        placeholder_body = (
            f"# {proj} — {comp_slug} — latest scan\n\n"
            f"_Awaiting first security scan from the central pipeline._\n\n"
            f"This document will be overwritten on every release. For the immutable "
            f"per-commit archive, see the `history/` folder."
        )
        create_document(api_key, base_url, collection_id, "latest", parent_id, placeholder_body)

    # Pre-create the `history` folder so the first scan's history doc lands
    # cleanly without racing on folder creation.
    history_id = find_document_with_retry(api_key, base_url, collection_id, "history", parent_id)
    if history_id:
        print(f"  ✓ history folder already exists (id={history_id})")
    else:
        print(f"  + creating 'history' folder")
        create_document(
            api_key, base_url, collection_id, "history", parent_id,
            text="# history\n\nPer-commit scan archive. Retention applied automatically by the uploader.",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--short-code', required=True,
                        help="App short code (e.g. NTH-AXT-FL-WA). Use _infra for non-app scans.")
    parser.add_argument('--components', required=True,
                        help="Comma-separated list of component names (e.g. iam,fleet,telematics,audit). Use 'app' for single-image apps.")
    parser.add_argument('--project-name', required=False, default='',
                        help="Human-readable name (e.g. FleetLink) used in placeholder bodies.")
    args = parser.parse_args()

    api_key = os.environ.get('OUTLINE_API_KEY')
    base_url = os.environ.get('OUTLINE_BASE_URL')
    collection_id = os.environ.get('OUTLINE_COLLECTION_ID')

    missing = [k for k, v in [
        ('OUTLINE_API_KEY', api_key),
        ('OUTLINE_BASE_URL', base_url),
        ('OUTLINE_COLLECTION_ID', collection_id),
    ] if not v]
    if missing:
        raise SystemExit(f"Missing env: {', '.join(missing)}")

    components = [c.strip() for c in args.components.split(',') if c.strip()]
    if not components:
        raise SystemExit("--components must list at least one component")

    print(f"Bootstrapping Outline folders for {args.short_code} (slug: {slug(args.short_code)})")
    print(f"Components: {', '.join(components)}")
    print(f"Project name: {args.project_name or '(none)'}")

    for comp in components:
        bootstrap_one_component(api_key, base_url, collection_id, args.short_code, comp, args.project_name)

    print(f"\n✅ Bootstrap complete for {args.short_code}: {len(components)} component(s).")


if __name__ == "__main__":
    main()
