#!/usr/bin/env python3
"""Publish a Nexounel release to Forgejo (Gitea-compatible API).

Creates (or reuses) a Forgejo release for the given tag and uploads the
release artifacts (tarball + offline bundle + .sha256 sidecars).

Usage:
    python3 scripts/release/forgejo-publish.py --version v0.4.0 --dist dist/

Environment (no secrets in this file, ever):
    FORGEJO_TOKEN   Forgejo API token with write:repository scope (required).
    FORGEJO_URL     Forgejo base URL. Default: https://time.plutus.bond:8444
    FORGEJO_REPO    Repository as owner/name. Default: mashani/Nexounel

The token is read from the environment only. In CI it comes from the
FORGEJO_TOKEN secret. Never pass it on the command line (it would be
visible in the process list) and never write it to a file.

Behaviour:
- The release is found by tag; if it does not exist it is created
  (name = the tag, body = a short release note). If it exists it is
  reused.
- Every file in --dist matching nexounel-<version>-* is uploaded.
  An asset with the same name is deleted first, so re-running the
  script replaces the assets instead of failing on duplicates.
- After each upload the asset's size is verified against the local
  file size. The script exits non-zero on any failure.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def api_request(base_url, token, method, path, data=None, content_type=None):
    """One Forgejo API call. Returns (status, parsed JSON or None)."""
    url = base_url.rstrip("/") + "/api/v1" + path
    headers = {
        "Accept": "application/json",
        "Authorization": "token " + token,
    }
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read()
            if not body:
                return resp.status, None
            return resp.status, json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = {"message": body}
        return exc.code, parsed


def get_release_by_tag(base_url, token, owner, repo, tag):
    status, body = api_request(
        base_url, token, "GET",
        "/repos/%s/%s/releases/tags/%s" % (owner, repo, urllib.parse.quote(tag)),
    )
    if status == 200:
        return body
    if status == 404:
        return None
    raise RuntimeError("get release by tag failed: HTTP %s: %s" % (status, body))


def create_release(base_url, token, owner, repo, tag):
    payload = json.dumps({
        "tag_name": tag,
        "name": tag,
        "body": "Nexounel %s — DNS tunnel through public resolvers.\n\n"
                "Verify: `sha256sum -c nexounel-%s-offline.tar.gz.sha256`\n" % (tag, tag),
        "draft": False,
        "prerelease": False,
    }).encode("utf-8")
    status, body = api_request(
        base_url, token, "POST",
        "/repos/%s/%s/releases" % (owner, repo),
        data=payload, content_type="application/json",
    )
    if status not in (200, 201):
        raise RuntimeError("create release failed: HTTP %s: %s" % (status, body))
    return body


def list_assets(base_url, token, owner, repo, release_id):
    status, body = api_request(
        base_url, token, "GET",
        "/repos/%s/%s/releases/%s/assets" % (owner, repo, release_id),
    )
    if status != 200:
        raise RuntimeError("list assets failed: HTTP %s: %s" % (status, body))
    return body or []


def delete_asset(base_url, token, owner, repo, release_id, asset_id):
    status, body = api_request(
        base_url, token, "DELETE",
        "/repos/%s/%s/releases/%s/assets/%s" % (owner, repo, release_id, asset_id),
    )
    if status not in (200, 204):
        raise RuntimeError("delete asset failed: HTTP %s: %s" % (status, body))


def upload_asset(base_url, token, owner, repo, release_id, path):
    filename = os.path.basename(path)
    with open(path, "rb") as fh:
        data = fh.read()
    query = urllib.parse.urlencode({"name": filename})
    status, body = api_request(
        base_url, token, "POST",
        "/repos/%s/%s/releases/%s/assets?%s" % (owner, repo, release_id, query),
        data=data, content_type="application/octet-stream",
    )
    if status not in (200, 201):
        raise RuntimeError("upload %s failed: HTTP %s: %s" % (filename, status, body))
    if body is None or body.get("size") != len(data):
        raise RuntimeError(
            "upload %s size mismatch: local %d, remote %s"
            % (filename, len(data), None if body is None else body.get("size")))
    return body


def main():
    parser = argparse.ArgumentParser(description="Publish a Nexounel release to Forgejo.")
    parser.add_argument("--version", required=True, help="Release tag, e.g. v0.4.0")
    parser.add_argument("--dist", required=True, help="Directory with the release artifacts")
    parser.add_argument("--url", default=os.environ.get("FORGEJO_URL", "https://time.plutus.bond:8444"),
                        help="Forgejo base URL (default: $FORGEJO_URL or https://time.plutus.bond:8444)")
    parser.add_argument("--repo", default=os.environ.get("FORGEJO_REPO", "mashani/Nexounel"),
                        help="Repository owner/name (default: $FORGEJO_REPO or mashani/Nexounel)")
    args = parser.parse_args()

    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        print("error: FORGEJO_TOKEN is not set", file=sys.stderr)
        return 2
    if "/" not in args.repo:
        print("error: --repo must be owner/name, got %r" % args.repo, file=sys.stderr)
        return 2
    owner, repo = args.repo.split("/", 1)

    prefix = "nexounel-%s-" % args.version
    files = sorted(
        os.path.join(args.dist, name)
        for name in os.listdir(args.dist)
        if name.startswith(prefix)
    )
    if not files:
        print("error: no artifacts matching %s* in %s" % (prefix, args.dist), file=sys.stderr)
        return 2
    for path in files:
        if not os.path.isfile(path):
            print("error: %s is not a file" % path, file=sys.stderr)
            return 2

    print("Forgejo: %s  repo: %s  tag: %s" % (args.url, args.repo, args.version))
    release = get_release_by_tag(args.url, token, owner, repo, args.version)
    if release is None:
        print("creating release %s ..." % args.version)
        release = create_release(args.url, token, owner, repo, args.version)
    else:
        print("release %s exists (id %s), reusing it" % (args.version, release["id"]))
    release_id = release["id"]

    existing = {asset["name"]: asset["id"] for asset in list_assets(args.url, token, owner, repo, release_id)}
    for path in files:
        filename = os.path.basename(path)
        if filename in existing:
            print("replacing existing asset %s ..." % filename)
            delete_asset(args.url, token, owner, repo, release_id, existing[filename])
        print("uploading %s (%d bytes) ..." % (filename, os.path.getsize(path)))
        upload_asset(args.url, token, owner, repo, release_id, path)
        print("  %s OK" % filename)

    print("Forgejo release %s published: %d asset(s)" % (args.version, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
