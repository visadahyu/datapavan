#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks, before a push, that every lab image's packages still install: what CI's lab images fetch from outside.

    scripts/lab-pins.py              run each Dockerfile's install steps as written, the installs simulated (Docker)
    scripts/lab-pins.py --list       the install steps it would run, without Docker
    scripts/lab-pins.py --self-test  its reading of made-up Dockerfiles and of every real one, without Docker

On 2026-11-24 Alpine rebuilt python3 3.14.10 as r2 and dropped r1, and CI's dns shard could not build the DNS lab's
image (docs/ci-flakes.md, run 45354185822). Nothing in the repository had changed. This reads every Dockerfile of the
commit to be pushed (HEAD, as git has it: a working copy that differs is named, and checked as committed) and runs the
install steps of each stage (a RUN with `apt-get install`, `apt install` or `apk add`) as
the build runs them: in a container of the stage's base image, by its digest, with the stage's ARG defaults and ENV
values, each step its own `/bin/sh -c`. Shims in a folder of their own, put first on the PATH, turn the install into a
simulated one (`apt-get -s`, `apt -s`, `apk add --simulate`) and the retries' `sleep` into two seconds, so that the
step's own
sources (the Debian snapshot its image names), options, retries and pins are what is checked, and nothing is
installed: the package index is fetched, and every package and version must resolve with its dependencies.

It also refuses what would make that check untrue, from the file and line: a FROM that is not pinned by digest (a tag
moves), an install step on a stage built from another stage, or one after an instruction that changes the image
(COPY, another RUN, WORKDIR, USER, SHELL), since the step would then run on an image other than the build's; and any
form it does not read: a parser directive, a heredoc, an exec-form or flagged (`--mount`) install step, an
instruction it does not know.

What it does not see, by its way of working:
- a command after the install, in the same step or in a later install step of the stage, that needs what was to be
  installed fails here though the build passes: a false failure, never a false pass (none of today's stages has one);
- an install called by its full path (`/usr/bin/apt-get`) passes the shims and really installs, and a stage whose
  installs are all so called fails here as having simulated nothing: call them by name;
- a simulated install fetches no package, so a file missing from the archive behind a listed version passes (the
  snapshot keeps every file it lists);
- CI keeps the proxy lab's and the WireGuard peer's layers in its cache, so a pin broken here fails CI there only once
  that cache moves: still a break, found before it lands;
- what the build stages fetch (a git clone at a commit, crates, Go modules, all fixed by checksums but the clone) and
  the base images of stages with no install step are not read; `FROM --platform` is read past, so the packages
  resolved are this machine's architecture's.

Part of `scripts/check.sh prepush`; `scripts/check.sh data` runs `--self-test`, so that a Dockerfile this cannot read
fails CI rather than going unchecked here.
"""
import concurrent.futures
import dataclasses
import os
import pathlib
import re
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A RUN that installs packages: apt-get or apt with install, apk with add, in one command of the step.
INSTALL = re.compile(r"\b(?:apt-get|apt)\b[^;&|\n]*?\binstall\b|\bapk\b[^;&|\n]*?\badd\b")

# Instructions that change nothing an install step sees; any other one (COPY, ADD, RUN, WORKDIR, USER, SHELL,
# VOLUME, ONBUILD) before an install step refuses the stage.
NEUTRAL = {"ARG", "ENV", "LABEL", "EXPOSE", "MAINTAINER", "STOPSIGNAL", "HEALTHCHECK", "CMD", "ENTRYPOINT"}

# Every instruction Docker knows; another word fails the check rather than being read past.
KNOWN = NEUTRAL | {"FROM", "RUN", "COPY", "ADD", "WORKDIR", "USER", "SHELL", "VOLUME", "ONBUILD"}

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")

# A parser directive, read by Docker from the first lines only (`# syntax=`, `# escape=`, `# check=`).
DIRECTIVE = re.compile(r"^#\s*(syntax|escape|check)\s*=", re.IGNORECASE)

# Run in the container before the steps: the shims, in a folder put first on the PATH whatever the image's own order,
# then each step as Docker runs a RUN, `/bin/sh -c`, in order.
SETUP = r"""set -eu
mkdir -p /lab-pins/bin
for tool in apt-get apt apk; do
    real=$(command -v "$tool") || continue
    case "$tool" in apk) verb=add flag=--simulate ;; *) verb=install flag=-s ;; esac
    printf '#!/bin/sh\nfor a in "$@"; do if [ "$a" = %s ]; then echo "simulated: %s $*" >&2; exec %s %s "$@"; fi; done\nexec %s "$@"\n' \
        "$verb" "$tool" "$real" "$flag" "$real" >"/lab-pins/bin/$tool"
    chmod 755 "/lab-pins/bin/$tool"
done
real=$(command -v sleep)
printf '#!/bin/sh\nexec %s 2\n' "$real" >/lab-pins/bin/sleep
chmod 755 /lab-pins/bin/sleep
export PATH="/lab-pins/bin:$PATH"
i=1
while [ "$i" -le "$LAB_PINS_STEPS" ]; do
    eval "step=\$LAB_PINS_STEP_$i"
    /bin/sh -c "$step"
    i=$((i + 1))
done
"""

# Each container's bound, its image's pull and all its stage's steps: an index fetch of a few megabytes and a
# resolution take seconds.
STEP_SECONDS = 180


@dataclasses.dataclass
class Stage:
    """One stage of a Dockerfile: its base image, the line of its FROM, its ARGs and ENVs, and its install steps."""

    path: str
    line: int
    image: str
    env: dict = dataclasses.field(default_factory=dict)
    steps: list = dataclasses.field(default_factory=list)
    changed: str = ""
    from_stage: bool = False


def instructions(text):
    """The Dockerfile's instructions as (line, keyword, arguments): continuations joined, comment lines dropped."""
    out, pending, start = [], None, 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        if pending is None:
            pending, start = "", number
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1]
            continue
        pending += line
        keyword, _, arguments = pending.strip().partition(" ")
        out.append((start, keyword.upper(), arguments.strip()))
        pending = None
    if pending is not None:
        keyword, _, arguments = pending.strip().partition(" ")
        out.append((start, keyword.upper(), arguments.strip()))
    return out


def expand(value, variables):
    """`$NAME` and `${NAME}` replaced from `variables`, as Docker does in ENV, ARG and FROM; others left as written."""
    return re.sub(
        r"\$(?:\{(\w+)\}|(\w+))",
        lambda m: variables.get(m.group(1) or m.group(2), m.group(0)),
        value,
    )


def read(path, text):
    """The stages of the Dockerfile `text` at `path`, and what refuses it, each with its file and line."""
    stages, problems, names, global_args = [], [], set(), {}
    stage = None
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        if not raw.lstrip().startswith("#"):
            break
        if DIRECTIVE.match(raw.strip()):
            problems.append(f"{path}:{number}: a parser directive, which this check does not read")
    for line, keyword, arguments in instructions(text):
        where = f"{path}:{line}"
        if keyword not in KNOWN:
            problems.append(f"{where}: {keyword}, an instruction this check does not know")
            continue
        if "<<" in arguments and keyword in {"RUN", "COPY", "ADD"}:
            problems.append(f"{where}: a heredoc, which this check does not read")
            if stage is not None and not stage.changed:
                stage.changed = f"{keyword} at line {line}"
            continue
        if keyword == "FROM":
            words = [w for w in shlex.split(arguments) if not w.startswith("--")]
            image = expand(words[0], global_args) if words else ""
            stage = Stage(path, line, image, from_stage=image.lower() in names)
            stages.append(stage)
            if image != "scratch" and not stage.from_stage and not DIGEST.search(image):
                problems.append(f"{where}: FROM {image} is not pinned by digest (@sha256:...): a tag moves")
            if len(words) >= 3 and words[1].upper() == "AS":
                names.add(words[2].lower())
            continue
        if keyword == "ARG":
            name, has, default = arguments.partition("=")
            name = name.strip()
            if stage is None:
                global_args[name] = expand(default.strip().strip('"'), global_args) if has else ""
            elif has:
                stage.env[name] = expand(shlex.split(default)[0] if default.strip() else "", stage.env)
            elif global_args.get(name):
                stage.env[name] = global_args[name]
            continue
        if stage is None:
            continue
        if keyword == "ENV":
            words = shlex.split(arguments)
            if words and "=" not in words[0]:
                # The old form, `ENV NAME value with spaces`.
                stage.env[words[0]] = expand(arguments.split(None, 1)[1] if len(words) > 1 else "", stage.env)
            else:
                for word in words:
                    name, _, value = word.partition("=")
                    stage.env[name] = expand(value, stage.env)
            continue
        if keyword == "RUN" and INSTALL.search(arguments):
            if arguments.lstrip().startswith("["):
                problems.append(f"{where}: an install step in exec form, which this check does not run")
            elif arguments.lstrip().startswith("--"):
                problems.append(f"{where}: an install step with flags (--mount, --network), which this check does not run")
            elif stage.from_stage:
                problems.append(f"{where}: an install step on a stage built from another stage, which this check does not run")
            elif stage.changed:
                problems.append(
                    f"{where}: an install step after {stage.changed}, so it would run here on an image other than the build's"
                )
            else:
                stage.steps.append((line, arguments))
            continue
        if keyword not in NEUTRAL and not stage.changed:
            stage.changed = f"{keyword} at line {line}"
    return [s for s in stages if s.steps], problems


def git(*arguments):
    """git's output for `arguments` in the repository; exits with git's own message if it cannot."""
    try:
        done = subprocess.run(["git", "-C", str(ROOT), *arguments], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("lab-pins.py reads the Dockerfiles from git, and git is not here")
    if done.returncode != 0:
        sys.exit(f"lab-pins.py: git {' '.join(arguments)}: {done.stderr.strip()}")
    return done.stdout


def dockerfiles():
    """Every Dockerfile of HEAD, the commit a push sends."""
    listed = git("ls-tree", "-r", "-z", "--name-only", "HEAD").split("\0")
    return sorted(p for p in listed if p and re.search(r"(^|/)(Dockerfile|[^/]*\.Dockerfile)$", p))


def everything():
    """The install stages of every Dockerfile as HEAD has it, every problem found reading them, and the files whose
    working copy differs, or that git does not hold yet."""
    stages, problems = [], []
    for path in dockerfiles():
        found, wrong = read(path, git("show", f"HEAD:{path}"))
        stages += found
        problems += wrong
    unsaved = [
        line[3:]
        for line in git("status", "--porcelain", "--untracked-files=all").splitlines()
        if re.search(r"(^|/)(Dockerfile|[^/]*\.Dockerfile)$", line[3:])
    ]
    return stages, problems, unsaved


def run(stage, number):
    """Runs `stage`'s install steps in a container of its base image: (ok, what it printed)."""
    name = f"datapavan-prepush-{os.getpid()}-{number}"
    env = dict(stage.env)
    env["LAB_PINS_STEPS"] = str(len(stage.steps))
    for i, (_, step) in enumerate(stage.steps, 1):
        env[f"LAB_PINS_STEP_{i}"] = step
    command = ["docker", "run", "--rm", "--name", name, "--label", "org.visadahyu.datapavan=prepush"]
    for key, value in env.items():
        command += ["--env", f"{key}={value}"]
    command += ["--entrypoint", "/bin/sh", stage.image, "-c", SETUP]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=STEP_SECONDS)
    except subprocess.TimeoutExpired as late:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        said = "".join(part.decode(errors="replace") if isinstance(part, bytes) else part or "" for part in (late.stdout, late.stderr))
        return False, f"{said}\nover {STEP_SECONDS} s"
    return done.returncode == 0, done.stdout + done.stderr


def check():
    """Runs every install stage, four at a time, and says what each resolved or how it failed."""
    stages, problems, unsaved = everything()
    for path in unsaved:
        print(f"  note: {path} is not as HEAD has it: checked as committed, which is what a push sends")
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("Docker is not running here: the lab images' pins need it (LABPINS=skip to leave them out)", file=sys.stderr)
        return 1
    failed = 0
    names = [f"datapavan-prepush-{os.getpid()}-{n}" for n in range(1, len(stages) + 1)]
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    try:
        futures = {pool.submit(run, stage, n): stage for n, stage in enumerate(stages, 1)}
        for future in concurrent.futures.as_completed(futures):
            stage = futures[future]
            ok, output = future.result()
            label = f"{stage.path}:{stage.line} ({stage.image.split('@')[0]})"
            simulated = [l.removeprefix("simulated: ") for l in output.splitlines() if l.startswith("simulated: ")]
            if ok and simulated:
                print(f"  ok {label}")
                for line in simulated:
                    print(f"     {line}")
            else:
                failed = 1
                why = "" if ok else ", which failed"
                print(f"{label}: its install steps{why}{'' if simulated else ' simulated nothing'}:", file=sys.stderr)
                print("\n".join(output.splitlines()[-25:]), file=sys.stderr)
    finally:
        # However it ended (Ctrl-C included): no run starts after this, and none of this check's containers stays.
        pool.shutdown(wait=True, cancel_futures=True)
        subprocess.run(["docker", "rm", "-f", *names], capture_output=True)
    return failed


SAMPLE = """\
# A comment line.
ARG BASE=debian:trixie-slim@sha256:%(digest)s
FROM golang:1.27@sha256:%(digest)s AS build
RUN go build ./...
FROM ${BASE}
ARG VERSION=1.2-3
ENV DEBIAN_FRONTEND=noninteractive GOFLAGS="-trimpath -mod=readonly"
ENV OLD form with spaces
LABEL a=b
RUN set -eu; \\
    # a comment inside the step
    for attempt in 1 2 3; do \\
        apt-get update && apt-get install -y --no-install-recommends "tool=$VERSION" && break; \\
        [ "$attempt" -lt 3 ]; sleep 15; \\
    done
RUN apk add --no-cache python3~3.14
COPY x /x
RUN apt-get install -y late
FROM alpine:3.24
RUN apk add nginx
FROM build
RUN apt-get install -y onstage
FROM debian:trixie-slim@sha256:%(digest)s
RUN --mount=type=cache,target=/var/cache/apt apt-get install -y cached
RUN ["apt-get", "install", "-y", "exec"]
RUN <<EOF
apt-get install -y here
EOF
FROME debian
"""

# Parser directives come first or not at all.
DIRECTED = """\
# syntax=docker/dockerfile:1
FROM debian:trixie-slim@sha256:%(digest)s
"""


def self_test():
    """Reads the sample and every real Dockerfile, without Docker."""
    stages, problems = read("sample", SAMPLE % {"digest": "0" * 64})
    assert [s.line for s in stages] == [5, 19], stages
    stage = stages[0]
    assert stage.image == "debian:trixie-slim@sha256:" + "0" * 64, stage.image
    assert stage.env == {
        "VERSION": "1.2-3",
        "DEBIAN_FRONTEND": "noninteractive",
        "GOFLAGS": "-trimpath -mod=readonly",
        "OLD": "form with spaces",
    }, stage.env
    assert [line for line, _ in stage.steps] == [10, 16], stage.steps
    assert "comment" not in stage.steps[0][1] and 'apt-get install -y --no-install-recommends "tool=$VERSION"' in stage.steps[0][1]
    expected = [
        "sample:18: an install step after COPY at line 17",
        "sample:19: FROM alpine:3.24 is not pinned by digest",
        "sample:22: an install step on a stage built from another stage",
        "sample:24: an install step with flags",
        "sample:25: an install step in exec form",
        "sample:26: a heredoc",
        "sample:27: APT-GET, an instruction this check does not know",
        "sample:28: EOF, an instruction this check does not know",
        "sample:29: FROME, an instruction this check does not know",
    ]
    assert len(problems) == len(expected) and all(p.startswith(e) for p, e in zip(problems, expected)), problems
    _, directed = read("directed", DIRECTED % {"digest": "0" * 64})
    assert directed == ["directed:1: a parser directive, which this check does not read"], directed
    assert not INSTALL.search("apt-get update && echo install"), "an install after another command"
    assert INSTALL.search("apt-get -o A=b install -y x") and INSTALL.search("apk --no-cache add x")
    assert INSTALL.search("apt install -y x"), "apt's own form"
    real, wrong, _ = everything()
    assert not wrong, wrong
    assert real, "no install step in any tracked Dockerfile"
    print(f"lab-pins.py: self-test passed ({len(real)} install stages in {len(dockerfiles())} Dockerfiles)")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:] == ["--list"]:
        stages, problems, _ = everything()
        for stage in stages:
            for line, step in stage.steps:
                print(f"{stage.path}:{line} ({stage.image}): {step}")
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    if sys.argv[1:]:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    return check()


if __name__ == "__main__":
    sys.exit(main())
