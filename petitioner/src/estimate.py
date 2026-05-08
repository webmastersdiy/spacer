"""
Local upper-bound estimate for the action+result delay window (§5.2).

Per design-docs/2026-05-05-0948-architecture-overview.md §5.2:
- The petitioner computes the estimate locally from its own view of
  similar global activity.
- No estimate information comes from the arbiter, and the arbiter
  offers no guarantee on the bound.
- The exact local-estimation method is open (§7).

This module is the scaffolding implementation called out in sp-77lxs.9:
"a placeholder estimate that returns an upper bound is acceptable for
early scaffolding." It does not yet observe global activity; that is
deferred to the bead that takes on §5.2 in earnest.

Two regimes:

- Test deployment (PETCLI_TEST_TIMING=1): the petitioner-side
  configuration declares that the arbiter is in test mode (§10).
  Test-mode windows are 5-15s for action delay and 5-15s for result
  delay; the worst-case sum is 30s.
- Default: production-like deployment. Action and result delays both
  have ~12h floors per §4.6 and are randomized within dynamic windows.
  Without the dynamic-window calculation (sp-77lxs.3) the petitioner
  has no real observation to base a tight estimate on, so we return
  24h - comfortably above the 2*12h floor while staying inside a span
  the AI can usefully reason about.

Both regimes are explicitly upper bounds. The "still within window"
vs "assume lost" decision (§5.2) tolerates an upper bound that is too
loose (extra waiting) far better than one that is too tight (false
"assume lost" before the result actually arrives).
"""
import os

# Test mode: action upper 15s + result upper 15s = 30s (§10).
_TEST_UPPER_BOUND_S = 30.0

# Production placeholder: 24h sits above the 2 * ~12h floor of §4.6
# while staying inside a single AI reasoning horizon.
_DEFAULT_UPPER_BOUND_S = 86400.0


def action_plus_result_window_s():
    """Return the local upper-bound estimate, in seconds, of how long
    until a submitted state-changing action's result becomes
    pollable. Local-only by design (§5.2): never calls the arbiter.

    Mode selection mirrors the arbiter's timing._mode() pattern: only
    the exact string "1" enables the test-deployment regime, so a
    typo or capitalized variant does not silently fall through to the
    compressed window.
    """
    if os.environ.get("PETCLI_TEST_TIMING") == "1":
        return _TEST_UPPER_BOUND_S
    return _DEFAULT_UPPER_BOUND_S


if __name__ == "__main__":
    import sys

    # Default regime: 24h upper bound. Clear the env var first so a
    # caller's setting does not pollute the default check.
    if "PETCLI_TEST_TIMING" in os.environ:
        del os.environ["PETCLI_TEST_TIMING"]
    assert (
        action_plus_result_window_s() == _DEFAULT_UPPER_BOUND_S
    ), "default regime must return 24h upper bound"

    # Test-deployment regime: 30s upper bound.
    os.environ["PETCLI_TEST_TIMING"] = "1"
    assert (
        action_plus_result_window_s() == _TEST_UPPER_BOUND_S
    ), "PETCLI_TEST_TIMING=1 must return 30s upper bound"

    # Anything other than the exact string "1" stays in the default
    # regime - matches arbiter timing._mode()'s strict-opt-in pattern.
    for misset in ("yes", "true", "TEST", "0", "", "  1"):
        os.environ["PETCLI_TEST_TIMING"] = misset
        assert action_plus_result_window_s() == _DEFAULT_UPPER_BOUND_S, misset

    print("OK: estimate placeholder upper bound is correct in both regimes")
    sys.exit(0)
