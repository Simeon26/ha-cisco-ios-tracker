# Contributing

Thanks for helping to improve Cisco IOS Tracker. This guide covers the development setup, the checks every change must pass, and how releases are made.

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Git. uv installs Python 3.14 for you.

```bash
git clone https://github.com/Simeon26/ha-cisco-ios-tracker.git
cd ha-cisco-ios-tracker

uv python install 3.14
uv venv --python 3.14 .venv
source .venv/bin/activate

uv pip install -r requirements_test.txt -r requirements_lint.txt
pre-commit install
```

`requirements_test.txt` installs [pytest-homeassistant-custom-component](https://github.com/MatthewFlamm/pytest-homeassistant-custom-component) (phcc), which brings in the matching Home Assistant release, pytest and the test plugins. `requirements_lint.txt` installs ruff, mypy and pre-commit.

## Project layout

| Path | Contents |
|---|---|
| `custom_components/cisco_ios_tracker/` | The integration. Everything it needs at runtime must be in this folder. |
| `custom_components/cisco_ios_tracker/client.py` | The asyncssh client and the `show` command parsers. It has no Home Assistant imports, so it can be tested on its own. |
| `custom_components/cisco_ios_tracker/translations/en.json` | The only translation file. Custom integrations don't use `strings.json`, and `[%key:...%]` references are not resolved, so write every string out in full. |
| `custom_components/cisco_ios_tracker/brand/` | `icon.png` (256x256) and `icon@2x.png` (512x512), served by Home Assistant 2026.3 and later. |
| `tests/` | pytest tests, command output fixtures in `tests/fixtures/` and syrupy snapshots in `tests/snapshots/`. |

Don't add a `manifest.json` anywhere else in the repository, including test fixtures. The hassfest action validates every `manifest.json` it finds.

## Running the tests

```bash
pytest              # full run with coverage; fails below 95%
pytest -n auto      # the same, in parallel
pytest tests/test_client.py -k arp   # a subset
```

Some client tests start a real asyncssh server on `127.0.0.1`, so they need local sockets. They use the `socket_enabled` fixture.

If you change entities, the device registry or diagnostics, update the snapshots and review the diff before you commit:

```bash
pytest --snapshot-update
git diff tests/snapshots/
pytest              # run again without the flag to confirm
```

The config flow must stay at 100% coverage, and the whole integration at 95% or more.

## Linting and type checking

```bash
ruff check .
ruff format --check .
mypy
pre-commit run --all-files
```

The configuration for ruff, mypy, pytest and coverage is in `pyproject.toml`. The rules follow Home Assistant core: docstrings on every module, class and function, full type hints, lazy `%s` logging, no bare `except Exception` outside the config flow and background tasks, and small `try` blocks. Fix the underlying problem rather than adding `# noqa` or `# type: ignore`.

### Running hassfest locally (optional)

The **Validate** workflow runs hassfest on every push. To run it yourself, use the same Docker image:

```bash
docker run --rm -v "$(pwd)":/github/workspace ghcr.io/home-assistant/hassfest
```

Or, from a checkout of [home-assistant/core](https://github.com/home-assistant/core) with its development environment active:

```bash
python -m script.hassfest --action validate \
  --integration-path /path/to/ha-cisco-ios-tracker/custom_components/cisco_ios_tracker
```

## Continuous integration

| Workflow | Jobs |
|---|---|
| `.github/workflows/validate.yml` | hassfest and the HACS action (`category: integration`, no `ignore`). Runs on pushes to `main`, pull requests, daily and on demand. |
| `.github/workflows/tests.yml` | Ruff and mypy, and pytest on Python 3.14 against two Home Assistant versions: the phcc pinned in `requirements_test.txt` (snapshots asserted), and the minimum version from `hacs.json` (phcc 0.13.317, Home Assistant 2026.3.1), where snapshots are regenerated instead of asserted because their output differs between releases. Snapshot-independent assertions, such as the diagnostics redaction checks, still run there. Runs weekly too, to catch breakage from new asyncssh and cryptography releases. Home Assistant itself only changes when you bump phcc, see below. |

Dependabot opens weekly pull requests for GitHub Actions and Python requirements. It ignores phcc, because every phcc bump needs a snapshot refresh.

The ruff and mypy pre-commit hooks run the versions installed from `requirements_lint.txt`, so a Dependabot bump of ruff applies to CI and to pre-commit at the same time. Dependabot doesn't update the other hook revisions (codespell and pre-commit-hooks). Run `pre-commit autoupdate` now and then, and open a pull request with the result.

## Bumping the tested Home Assistant version

Each phcc release pins exactly one Home Assistant release. To test against a newer one:

1. Pick the phcc version that matches the Home Assistant release you want from the [phcc release history](https://pypi.org/project/pytest-homeassistant-custom-component/#history). You can confirm the pin with:

   ```bash
   echo "pytest-homeassistant-custom-component==0.13.NNN" | uv pip compile --python-version 3.14.8 - | grep '^homeassistant=='
   ```

2. Update the pin in `requirements_test.txt`.
3. Reinstall: `uv pip install -r requirements_test.txt`.
4. Run `pytest --snapshot-update`, review `git diff tests/snapshots/`, then run `pytest` and the linters again.
5. Open a pull request.

### Raising the minimum Home Assistant version

Only raise it when the integration needs a newer API. Then update, in the same pull request:

- `homeassistant` in `hacs.json`,
- the phcc version of the **minimum HA** job in `.github/workflows/tests.yml`,
- the requirements in `README.md`,
- `CHANGELOG.md`.

## Making a release

Release tags use the form `vX.Y.Z` and must match `version` in the manifest without the `v`.

1. Update `version` in `custom_components/cisco_ios_tracker/manifest.json` and in `pyproject.toml`.
2. Move the **Unreleased** notes in `CHANGELOG.md` to a new section for the version, with today's date, and update the comparison links at the bottom.
3. Open a pull request and wait for both workflows to pass, then merge it into `main`.
4. Tag the merge commit and push the tag:

   ```bash
   git checkout main && git pull
   git tag -a v1.2.0 -m "v1.2.0"
   git push origin v1.2.0
   ```

5. The **Release** workflow runs the tests and validation again, checks that the tag matches the manifest version, and creates the GitHub release with the changelog section as its notes. If it fails, fix the problem, delete the tag (`git push --delete origin v1.2.0` and `git tag -d v1.2.0`) and tag again.

HACS uses the latest release to offer updates; without releases it falls back to the commit hash.

## Publishing to HACS checklist

Before you submit the repository to the HACS default list, make sure all of these are true:

- [ ] The repository is public on GitHub and not archived.
- [ ] The repository has a description, for example "Home Assistant presence detection from the ARP table of Cisco IOS and IOS-XE devices".
- [ ] The repository has topics, for example `home-assistant`, `hacs`, `hacs-integration`, `cisco`, `device-tracker`, `presence-detection`.
- [ ] Issues are enabled.
- [ ] GitHub detects the license as Apache-2.0 on the repository page.
- [ ] `custom_components/cisco_ios_tracker/brand/icon.png` exists (the HACS brands check needs it).
- [ ] The **Validate** workflow (hassfest and HACS, with no `ignore`) and the **Tests** workflow are green on `main`.
- [ ] A full GitHub release exists, created after those green runs, whose tag matches the manifest `version` (for example `v1.0.0` and `"version": "1.0.0"`).
- [ ] Optional: open a pull request to [hacs/default](https://github.com/hacs/default). Fork it, create a branch from `master`, add `Simeon26/ha-cisco-ios-tracker` to the `integration` file in alphabetical order, and fill in the template with links to the release and to the passing HACS and hassfest runs. Submit it from a personal account so maintainers can edit it. Until it is merged, users can add the repository as a custom repository.

## Reporting bugs and requesting features

Use the issue templates. For bugs, attach the diagnostics and a debug log, and remove any private data first.
