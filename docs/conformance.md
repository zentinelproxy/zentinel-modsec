# CRS conformance

The OWASP CRS ships a regression corpus: YAML files under
`tests/regression/tests/`, one per rule, each stage pairing a request with the
rule IDs that must (`expect_ids`) or must not (`no_expect_ids`) appear in the
log. Upstream drives it with go-ftw against a live server.
`tests/crs_conformance.rs` feeds the same YAML straight into the engine.

## What the gate measures

`crs_regression_corpus` loads `crs-setup.conf` and `rules/*.conf` from the
checkout, plus the setup the corpus documents (rule 900005: `DetectionOnly`,
paranoia level 4). For each stage it builds a transaction from the request,
runs phases 1 and 2, and compares `matched_rules()` with the expectation. A
stage passes when every expected ID is present and no forbidden ID is.

Stages are skipped when they cannot be driven from here (`encoded_request`) or
do not assert rule IDs (`status`, `match_regex`). The test fails if more than
`EXPECTED_SKIPS_MAX` (60) are skipped, so coverage cannot shrink unnoticed.

The run prints the pass count, the files with the most failures, and the rule
IDs most often missing or spurious:

```
CRS regression corpus: 4949/5184 passing (95.5%), 41 skipped
```

The test then asserts `pass == MIN_PASSING`. Both directions fail: a loss is a
regression, a gain is a number that must be recorded so it cannot be lost
later without notice.

**What it does not measure.** In `DetectionOnly` nothing blocks, paranoia
gates do not fire, and the anomaly score never reaches 949110. The corpus says
whether individual rules match, not whether the WAF decides correctly.
`stock_crs_blocks_attacks_and_passes_ordinary_traffic`, in the same file, runs
stock CRS in blocking mode at the default paranoia level and asserts decisions
for ordinary requests and for attacks. A change to blocking behavior needs
that test, not the count.

## Running it

CI's `OWASP CRS conformance` job (`.github/workflows/ci.yml`) fetches one
pinned CRS commit and runs the test in release mode. To reproduce it:

```bash
mkdir -p test-rules/crs
git -C test-rules/crs init -q
git -C test-rules/crs fetch -q --depth 1 https://github.com/coreruleset/coreruleset.git \
    30cb436b261a9f5ec32a5a0677e17f3cfa1a8739
git -C test-rules/crs checkout -q FETCH_HEAD
cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
cargo test --release --test crs_conformance -- --nocapture
```

- `test-rules/` is gitignored.
- `CRS_DIR=/path/to/crs` uses another checkout. Any commit other than the
  pinned one gives a different count.
- `SKIP_CRS_CONFORMANCE=1` skips both tests. CI's unit-test job sets it because
  the conformance job runs them; the conformance job must never set it.
- Without a checkout and without the variable, the test fails with
  instructions instead of passing silently.
- Release mode takes seconds; a debug build takes minutes.

## Reading a count change

1. **Check what you are measuring.** The count only means something against
   the pinned commit, on a branch rebased on current `main`.
2. **Read the lists.** "rules that should have fired" and "rules that fired but
   must not" name the IDs. Compare them with the same run on `main`
   (`git stash`, or a second worktree) to see which stages moved.
3. **A gain** from a fix: set `MIN_PASSING` to the new count in the same
   commit and say in the PR which rules gained, as earlier PRs did ("all 17 new
   passes are in 922110").
4. **A loss**: find the regressed rules first. If the trade is deliberate (a
   stage that passed for the wrong reason, say), lower `MIN_PASSING` and
   explain which rules and why in the commit. Never lower it to make CI green.
5. **Two PRs that both move the count conflict**, even when Git merges them
   cleanly, because the effects do not add up reliably. Fixes interact: two
   transformation fixes can gain the same stage. After the first merges, the
   second rebases, re-runs the corpus, and sets the measured number.
6. **A change that should not affect matching** but moves the count is a bug
   until shown otherwise.

The README's history table records the steps that moved the figure. Update its
headline row when `MIN_PASSING` changes.

## Bumping the CRS commit

The corpus upstream keeps changing, so a new commit moves the count by itself.
Do it in a change of its own, not mixed with engine fixes:

1. Update `CRS_COMMIT` in the `conformance` job of `.github/workflows/ci.yml`.
2. Check out the new commit locally and run the test.
3. Set `MIN_PASSING` to the measured count and update the comment above it
   (CRS version and short commit).
4. Update the README: the corpus row of the conformance table, the
   `git checkout` line, and the passing figure. Update the commit in
   `.claude/CLAUDE.md` and in this file.
5. In the PR, list new failures by rule ID. Read them as new upstream tests
   first and as engine regressions second; new tests often cover behavior the
   engine never had.
6. If the number of skipped stages rises above `EXPECTED_SKIPS_MAX`, find out
   why before raising the cap.
