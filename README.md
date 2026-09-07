# Svod

Svod is a small Markdown and Git memory engine for coding agents. It
selects relevant records, validates writes and synchronizes repositories.
It has no model, vector database or persistent search server.

This distribution contains the engine, a neutral example configuration,
Git hooks, scheduler templates and tests. Private corpora, configuration,
integration fixtures and historical documents are not part of the package.

## Why this exists

The author works with a coding assistant across several agents (Claude
Code in a terminal and a desktop app, Codex, a Telegram bot) and several
machines, for a personal life and for more than one client at a time.
Every agent kept its own memory, or none, and the useful facts lived in
chat transcripts. Svod grew out of a short list of requirements that no
existing tool covered together:

1. **One memory for every agent.** A fact learned in one session must
   reach the next session of any agent on any machine, without a
   per-agent store and without pasting notes by hand.
2. **Plain files a human can read and edit.** Markdown records in Git,
   diffable, greppable, restorable from any clone. No model, vector
   database or search service in the read path.
3. **Clients never mix.** Each client corpus is its own repository; a
   machine or a corporate tool sees only the repositories it is allowed
   to clone. A session is pinned to one scope by its first message and
   never re-routed by a stray mention of another name. Isolation comes
   from what is not cloned, not from a prompt asking the model to behave.
4. **A small, deterministic context.** A hook injects the standing rules
   and at most a couple of matching records per prompt, within a fixed
   character budget. The selection is lexical and reproducible, so a
   miss can be explained and measured.
5. **Writes are validated, not trusted.** A record is accepted only when
   the same selection that serves prompts can find it (`probe`), when it
   carries a source and an observation date, when links resolve, when
   sections fit their delivery caps, and when a regression stand over
   known questions does not get worse.
6. **Secrets stay on the machine.** Added lines and every outgoing commit
   range are scanned before a push; without a scanner nothing is pushed.
7. **Machines converge without a human.** A timer fetches, rebases,
   verifies and pushes; ordinary divergence resolves itself, a real
   conflict is named in words and left to a person. `saved` means the
   server accepted the commit, not that a file was written locally.
8. **Nothing to back up except Git.** Pending candidates and caches are
   the only state outside the repositories; a fresh clone plus the hooks
   is a working installation.

The design decisions behind these points, and what was tried and removed,
are kept in the author's private notes; the engine here is the part that
does not depend on any particular corpus.

## Requirements

Linux or macOS, Python 3.10+, Git, and gitleaks supporting `detect` and
`git`. Python dependencies are from the standard library. Local drills
have been exercised with gitleaks 8.30.1. Git credentials and agent
configuration are managed separately.

## Try the isolated drill

```sh
python3 -u tests/drill_local.py
```

It creates temporary neutral repositories and local bare servers, checks
writes from two clones, rebase, offline retry, conflict preservation,
secret scanning across commit history, and recovery in a fresh clone.
The real gitleaks executable is required. No external Git server is used.
Recovery clones the engine from its Git HEAD: initialize a local Git
repository and commit the distribution first if using an unpacked archive.

For the included unit tests:

```sh
export MEMORY_CONFIG_DIR="$PWD/public/config"
export MEMORYCTL_STATE_DIR="$(mktemp -d)"
python3 -u -m unittest discover -s tests
```

Unit tests use neutral fixtures and a simulated scanner. The separate
drill exercises the actual scanner and CLI. These tests do not establish
that a scheduler or credentials work on another physical machine. The
public suite covers the writer, verifier, sync and config paths; the
router (`memorycontext`), `memoryrecall` and `memoryeval` are covered only
by the author's private suite, which reads a private corpus. A hygiene test
(`tests/test_hygiene.py`) keeps `lib/` free of functions without callers,
unused imports and helpers defined twice.

CLI output, refusal reasons and hook messages are in Russian; the code
identifiers and this README are English.

## Data layout

Keep data outside the engine repository:

```
data/                       a directory, not a Git repository
  global/                   shared session rules
  personal/                 optional personal records and inbox
  clients/acme/             optional client repository
config/                     topics.json, eval_questions.json, eval_baseline.json
state/                      pending, failed, sync and router state
```

Each data repository has a `main` branch, an `origin` remote, a
`memory/MEMORY.md` preamble and `.svod.json` containing
`{"scope":"global"}`, `{"scope":"personal"}`, or
`{"scope":"clients/acme"}`. Global is required; other repositories are
optional. Client repositories must be listed in `federationMembers`.

Copy `public/config` into a separate configuration repository and adapt it
to the actual workspace and corpus. Its example question expects
`reference_printer.md`, as supplied by the drill fixture. It is not a
usable retrieval baseline for an unrelated corpus. Configure your own
questions, expected records and evidence before writing real data.

```sh
export MEMORY_CONFIG_DIR=/absolute/path/to/config
export MEMORY_REPO=/absolute/path/to/data
export MEMORYCTL_STATE_DIR=/absolute/path/to/state
git -C /absolute/path/to/data/personal config core.hooksPath /absolute/path/to/svod/githooks
```

Install the hooks in each data repository. Configure the scheduler using
the provided systemd or launchd templates after reviewing their paths.
No private dotfiles installer is required. The templates assume the engine
checkout at `~/src/svod`; edit `WorkingDirectory`/`ExecStart` (systemd) or
the program path (launchd) if your checkout lives elsewhere. On
systemd, create the data and state directories before starting the service.
On macOS, replace `@@HOME@@` with an absolute home path before loading the
LaunchAgent.

## Read and write

```sh
bin/memory recall "question"
bin/memory explain reference_example
bin/memory status --fetch
bin/memory-sync
```

CLI scope is constrained by the calling directory and the configured
`scopeRoots`. Session hooks pin a project from the first message. Actual
access boundaries require separate repositories and credentials; a prompt
or scope marker is not access control.

A record is Markdown with frontmatter containing `type` (`user`,
`feedback`, `project`, `reference`), `title`, `index`, `source`,
`observed_at` and `probe`. The index is generated from record headers.
`listed: false` removes a personal record from search; client records are
reached through links in their topic rollup. The probe must find the record
using the router's own selection. Provenance must reflect the actual source
and observation date.

```sh
bin/memory remember --scope personal --id example-1 \
  --source agent --session example --content-type markdown \
  --file /absolute/path/to/record.md --projection /absolute/path/to/projection.json --json
```

The projection file can contain `{"record_slug":"reference_example"}`
when the record has a complete header. A client projection also supplies
`index_section` and `index_line`, with a link to the record in that line.

`--content-type manifest` accepts a JSON object with a nonempty `changes`
list and optional `base_revision` from the actual read. Each change has
`operation` (`put` or `remove`) and a unique `path` under `memory/`;
`put` also requires string `content`. A call affects one repository.

The writer checks the exact staged tree and outgoing commit range.
`saved` (exit 0) means the server accepted the commit. `pending` (4)
preserves a local candidate for retry, `failed` (2) preserves the refusal
with its reason, and `busy` (3) means the lock remained occupied.
Other startup errors are reported separately.

## Synchronization and recovery

`memory-sync` fast-forwards incoming commits, validates and pushes local
ones, rebases ordinary divergence, and retries pending candidates. A
conflict names the file and preserves the local branch. Keep both versions
before resolving; never discard unique local commits just to clear status.
The scheduler always attempts publication. Without gitleaks, outgoing
publication is refused, including a secret removed in a later commit.

Recovery consists of cloning compatible engine, configuration and data
revisions, reinstalling hooks, and running sync, status and a known recall.
Git preserves accepted facts. Losing a disk also loses unpushed commits
and local pending candidates unless they have a separate backup.

`memory-eval compare` checks regression against the configured baseline;
`selfcheck` exercises a deliberately empty and excessive result set.
`baseline` commits only the baseline file in the configuration repository
and reports whether its push succeeded. A green comparison is not proof
that every possible question can be answered.

## License

MIT. See [LICENSE](LICENSE).
