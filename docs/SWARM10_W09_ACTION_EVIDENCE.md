# SWARM10 W09 — source-bound Action H1/H2 evidence

This lane closes the acceptance-harness forgery gap without claiming product acceptance. It performs no network request, deploy, Passenger restart, Telegram authorization or write.

## Exact source binding

Both checkout-only CLIs derive the candidate commit from the executing Git checkout. They do not accept a caller-supplied candidate SHA. Before importing candidate schema modules, the verifier:

1. rejects Git/Python redirection environment variables and uses a fixed trusted Git executable;
2. rejects non-root, cross-checkout, parent/final symlink or reparse paths;
3. requires `git status --porcelain=v2 -z --untracked-files=all` to be empty;
4. rejects assume-unchanged and skip-worktree index flags;
5. captures one `HEAD^{commit}`, tree identity and exact `ls-tree` listing;
6. reads every tracked Python source used by the bridge/operations/tooling boundary through non-following, nonblocking regular-file descriptors and verifies its Git blob identity;
7. repeats cleanliness and exact-HEAD checks before candidate imports and before returning evidence.

The resulting binding includes the commit, tree, listing digest and verified Python-blob proof. H1 and H2 must carry the same binding.

## H1 — deployed schema comparison

```shell
python -I -B tools/verify_dev06_deployed_action.py \
  --source-checkout /absolute/path/to/clean/checkout \
  --observed-schema /outside/checkout/sanitized-openapi.json \
  --source-classification SOURCE_MOCK
```

Use `DEPLOYED_CAPTURE` only for a sanitized schema actually retrieved from the authorized production endpoint. Raw headers, credentials, setup values and Telegram data must never enter the capture. Matching schema output remains non-authorizing and sets `product_h1_pass=false`.

## H2 — sanitized read-only capture

```shell
python -I -B tools/verify_dev06_action_e2e.py \
  --source-checkout /absolute/path/to/clean/checkout \
  --capture /outside/checkout/sanitized-h2-capture.json
```

The capture accepts only a canonical READ Action operation, a successful status, exact H1 source binding, exact deployed SHA, bounded SHA-256 request/response fingerprints and boolean authority/read observations. `DEPLOYED_CAPTURE` additionally requires `telegram_read_observed=true`. Write operations and cross-checkout bindings fail closed. Output always sets `product_h2_pass=false` and `self_authorization=false`; an independent W10 verdict is still required.

## CI boundary

`.github/workflows/swarm10-w09-action-evidence.yml` runs on Python 3.11, checks out the event's exact head SHA, produces only synthetic sanitized fixtures outside the checkout, proves H1/H2 share that SHA and binding, runs adversarial tests plus current/history secret scans, and asserts that no deployment-arming file exists. It has read-only repository permission and no deployment job.
