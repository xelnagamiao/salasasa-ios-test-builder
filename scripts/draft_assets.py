#!/usr/bin/env python3
"""Exchange build files with an existing same-repository draft; never publish it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

API = "https://api.github.com"
MAX_ASSET_SIZE = 2 * 1024 ** 3


def gh(arguments, destination=None):
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("The draft step requires its repository GITHUB_TOKEN")
    result = subprocess.run(["gh", *arguments], stdout=destination or subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Error bodies can include temporary download URLs. Keep them out of logs.
        raise RuntimeError("GitHub draft API operation failed; check token permissions and the existing draft")
    return result.stdout


def api(endpoint, paginate=False):
    arguments = ["api", endpoint, "-H", "Accept: application/vnd.github+json",
                 "-H", "X-GitHub-Api-Version: 2022-11-28"]
    if paginate:
        arguments += ["--paginate", "--slurp"]
    data = json.loads(gh(arguments))
    return [item for page in data for item in page] if paginate else data


def repository():
    value = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise ValueError("GITHUB_REPOSITORY must identify the current build repository")
    return value


def ensure_draft(release, tag):
    if release.get("draft") is not True or release.get("published_at") is not None:
        raise ValueError("Refusing an already published release; input and output must remain drafts")
    if release.get("tag_name") != tag or not isinstance(release.get("id"), int):
        raise ValueError("Draft identity does not match the requested release")
    return release


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def anonymous_status(url, is_api=True):
    headers = {"Accept": "application/vnd.github+json" if is_api else "text/html",
               "User-Agent": "ios-draft-visibility-check"}
    if is_api:
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = urllib.request.Request(url, headers=headers)
    body = b""
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            status = response.status
            response_headers = response.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = exc.headers or {}
        try:
            if status in (403, 429) and exc.fp is not None:
                body = exc.read(2048)
        finally:
            exc.close()
    if status == 429:
        category = "rate-limit"
    elif status == 403 and response_headers.get("X-RateLimit-Remaining") == "0":
        category = "primary-rate-limit"
    elif status == 403 and response_headers.get("Retry-After") is not None:
        category = "secondary-rate-limit"
    elif status == 403 and b"rate limit" in body.lower():
        category = "rate-limit-response"
    elif status == 403:
        category = "forbidden; rate limit not confirmed"
    elif status == 404:
        category = "not-found"
    elif 300 <= status < 400:
        category = "redirect-refused"
    else:
        category = "unexpected-response"
    return status, category


def github_fallback_url(url, repo):
    if not isinstance(url, str) or not isinstance(repo, str):
        raise ValueError("GitHub API did not provide a usable fallback visibility URL")
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(parsed.path)
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment
            or not path.casefold().startswith(f"/{repo}/releases/".casefold())
            or "\\" in path or any(part in (".", "..") for part in path.split("/"))
            or any(ord(ch) < 32 for ch in url + path)):
        raise ValueError("Refusing fallback URL outside this repository's HTTPS GitHub release pages")
    return url


def require_anonymous_404(endpoint, fallback_url=None, repo=None):
    status, category = anonymous_status(API + endpoint)
    if status == 404:
        return
    if status in (403, 429) and "rate-limit" in category:
        print(f"Anonymous API check: HTTP {status} ({category}); checking GitHub web visibility.")
        url = github_fallback_url(fallback_url, repo)
        web_status, web_category = anonymous_status(url, is_api=False)
        if web_status == 404:
            print("Anonymous GitHub web check: HTTP 404 (not-found).")
            return
        raise ValueError(f"Anonymous GitHub web visibility check returned HTTP {web_status} "
                         f"({web_category}); expected HTTP 404 after API HTTP {status} ({category})")
    raise ValueError(f"Anonymous draft visibility check returned HTTP {status} ({category}); expected HTTP 404")


def check_private_draft(repo, release_id, tag, asset_id=None):
    release = ensure_draft(api(f"repos/{repo}/releases/{release_id}"), tag)
    require_anonymous_404(f"/repos/{repo}/releases/{release_id}", release.get("html_url"), repo)
    if asset_id is not None:
        asset = api(f"repos/{repo}/releases/assets/{asset_id}")
        if asset.get("id") != asset_id:
            raise ValueError("GitHub asset identity changed during the draft visibility check")
        require_anonymous_404(f"/repos/{repo}/releases/assets/{asset_id}", asset.get("browser_download_url"), repo)
    return release


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(args):
    repo = repository()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}", args.tag):
        raise ValueError("Use a simple release tag without whitespace or control characters")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.zip", args.filename):
        raise ValueError("ZIP asset filename must be a simple filename ending in .zip")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.sha256):
        raise ValueError("Expected SHA-256 is invalid")
    matches = [r for r in api(f"repos/{repo}/releases?per_page=100", True)
               if r.get("tag_name") == args.tag]
    if len(matches) != 1:
        raise ValueError("Expected exactly one existing accessible release with the requested tag")
    release = ensure_draft(matches[0], args.tag)
    assets = api(f"repos/{repo}/releases/{release['id']}/assets?per_page=100", True)
    matches = [asset for asset in assets if asset.get("name") == args.filename]
    if len(matches) != 1 or matches[0].get("state") != "uploaded":
        raise ValueError("Expected exactly one completely uploaded ZIP asset")
    asset = matches[0]
    if not 0 < asset.get("size", 0) < MAX_ASSET_SIZE:
        raise ValueError("ZIP asset has an invalid or unsupported size")
    expected = args.sha256.lower()
    if asset.get("digest") not in (None, "", "sha256:" + expected):
        raise ValueError("GitHub asset digest does not match the requested SHA-256")
    check_private_draft(repo, release["id"], args.tag, asset["id"])
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as stream:
        gh(["api", f"repos/{repo}/releases/assets/{asset['id']}",
            "-H", "Accept: application/octet-stream"], stream)
    if args.destination.stat().st_size != asset["size"] or file_digest(args.destination) != expected:
        raise ValueError("Downloaded ZIP size or SHA-256 does not match the requested export")
    check_private_draft(repo, release["id"], args.tag, asset["id"])
    args.state.write_text(json.dumps({"repository": repo, "releaseId": release["id"],
        "tag": args.tag, "inputAssetId": asset["id"], "inputFile": args.filename,
        "inputSha256": expected}, indent=2) + "\n", encoding="utf-8")
    print("Verified draft access and downloaded the matching Xcode export.")


def collect_outputs(output, staging, prefix, build_succeeded=False):
    staging.mkdir(parents=True, exist_ok=False)
    manifest = {"schemaVersion": 1, "status": "success" if build_succeeded else "failed", "assets": []}
    if not output.is_dir():
        return []
    candidates = sorted(output.iterdir()) if build_succeeded else []
    if build_succeeded:
        from ios_artifact import inspect_ipa
        ipas = [p for p in candidates if p.suffix == ".ipa" and p.is_file() and not p.is_symlink()]
        if len(ipas) != 1:
            raise ValueError("Successful build must contain exactly one validated unsigned IPA")
        verified = inspect_ipa(ipas[0])
        recorded = json.loads((output / "unsigned-ipa.json").read_text(encoding="utf-8"))
        if recorded != verified:
            raise ValueError("Unsigned IPA receipt does not match the final artifact")
        manifest["unsigned"] = True
        manifest["installableWithoutSigning"] = False
    for source in candidates:
        if source.is_symlink() or not source.is_file() or source.suffix not in (".ipa", ".json"):
            continue
        target = staging / (prefix + source.name)
        shutil.copyfile(source, target)
        digest = file_digest(target)
        manifest["assets"].append({"name": target.name, "originalName": source.name,
                                   "sha256": digest, "sizeBytes": target.stat().st_size})
        if source.suffix == ".ipa":
            target.with_name(target.name + ".sha256").write_text(
                f"{digest}  {target.name}\n", encoding="utf-8")
    logs_root = output / "logs"
    logs = [p for p in logs_root.rglob("*") if p.is_file() and not p.is_symlink()] \
        if logs_root.is_dir() and not logs_root.is_symlink() else []
    driver = output / "driver.log"
    if driver.is_file() and not driver.is_symlink():
        logs.append(driver)
    if logs:
        with zipfile.ZipFile(staging / (prefix + "build-logs.zip"), "w", zipfile.ZIP_DEFLATED) as archive:
            for log in logs:
                archive.write(log, str(log.relative_to(output)))
    (staging / (prefix + "handoff.json")).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = sorted(staging.iterdir())
    if any(p.stat().st_size >= MAX_ASSET_SIZE for p in files):
        raise ValueError("A build output exceeds the 2 GiB GitHub release asset limit")
    return files


def upload(args):
    repo = repository()
    state = json.loads(args.state.read_text(encoding="utf-8"))
    if state.get("repository") != repo or not isinstance(state.get("releaseId"), int):
        raise ValueError("Saved draft identity does not match this repository")
    if not re.fullmatch(r"[0-9]+", args.run_id) or not re.fullmatch(r"[0-9]+", args.attempt):
        raise ValueError("Invalid workflow run identity")
    check_private_draft(repo, state["releaseId"], state["tag"], state["inputAssetId"])
    prefix = f"run-{args.run_id}-{args.attempt}-"
    staging = args.output.parent / (prefix + "upload")
    files = collect_outputs(args.output, staging, prefix, args.build_succeeded == "true")
    if not files:
        print("No build outputs exist; the input draft remains unchanged.")
        return
    existing = api(f"repos/{repo}/releases/{state['releaseId']}/assets?per_page=100", True)
    if set(p.name for p in files) & set(a["name"] for a in existing):
        raise ValueError("Refusing to overwrite existing build outputs in the draft")
    # Uploading assets never changes draft=false. Do not use release create/edit/publish.
    gh(["release", "upload", state["tag"], *map(str, files), "--repo", repo])
    check_private_draft(repo, state["releaseId"], state["tag"])
    uploaded = api(f"repos/{repo}/releases/{state['releaseId']}/assets?per_page=100", True)
    uploaded_by_name = {a["name"]: a for a in uploaded}
    for path in files:
        asset = uploaded_by_name.get(path.name)
        if not asset or asset.get("state") != "uploaded" or asset.get("size") != path.stat().st_size:
            raise ValueError("Could not verify all uploaded draft outputs")
        if asset.get("digest") not in (None, "", "sha256:" + file_digest(path)):
            raise ValueError("An uploaded draft output failed its digest check")
        require_anonymous_404(f"/repos/{repo}/releases/assets/{asset['id']}", asset.get("browser_download_url"), repo)
    print(f"Saved {len(files)} outputs to the existing draft. Nothing was published.")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    get = commands.add_parser("download")
    get.add_argument("--tag", required=True)
    get.add_argument("--filename", required=True)
    get.add_argument("--sha256", required=True)
    get.add_argument("--destination", required=True, type=Path)
    get.add_argument("--state", required=True, type=Path)
    put = commands.add_parser("upload")
    put.add_argument("--state", required=True, type=Path)
    put.add_argument("--output", required=True, type=Path)
    put.add_argument("--run-id", required=True)
    put.add_argument("--attempt", required=True)
    put.add_argument("--build-succeeded", required=True, choices=("true", "false"))
    args = parser.parse_args()
    (download if args.command == "download" else upload)(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError, KeyError) as exc:
        print(f"Draft operation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
