# Examples

One small app per supported framework, plus a shared static frontend (`lure-frontend/`) that every app serves. They exist to show how trappsec is wired into each framework (initialization, `identify_user`, alert outputs, `trap`, `watch`) and to give the [end-to-end suite](../tests/e2e/README.md) one specification to test every SDK against.

## These are test fixtures, not deception patterns

The decoys in these apps are deliberately simple and identical across all of them, because the e2e suite asserts on their exact paths, fields, statuses and bodies. That makes them the opposite of what a real deployment needs. Don't copy them:

- **Paths and fields are shared by every example**, and anything shared across apps becomes a signature attackers learn. Real decoys are derived from your own app's routes, vocabulary and data model.
- **`lure-frontend/js/api.js` has client methods nothing calls**, pointing at trap routes. Uncalled methods for powerful capabilities are among the lures red-team reviewers most often spot as planted.
- **The profile honey field is a boolean admin flag.** In an app whose permissions are role-based, a field like that is foreign to the data model and stands out.
- **Some trap bodies are "too good to be true"**: a 200 with deployment details for any signed-in user, and metrics that change randomly on every call (there to exercise dynamic response bodies). Real decoys return the app's real 403 or stable values derived from the request.
- **Several traps share one generic retired-version response**, written from scratch rather than copied from how the app really answers.

To design deception for your own app, use the [`add-deception` agent skill](../plugins/trappsec/skills/add-deception/) or read [Baiting & Lures](https://trappsec.dev/baiting-and-lures/), which summarizes it.

## Running

See [tests/e2e/README.md](../tests/e2e/README.md) for running one example by hand or all of them through the harness.
