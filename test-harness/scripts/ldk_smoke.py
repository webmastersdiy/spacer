"""
Throwaway smoke test for ldk-node Python bindings against Mutinynet.

Run with the spacer venv:
    ~/spacer/test-harness/venv/bin/python ~/spacer/test-harness/scripts/ldk_smoke.py

NOTE: ldk-node has no PyPI release. The `ldk_node` package must be built
from source (Rust + uniffi-bindgen) and dropped into the venv's
site-packages, or pip-installed from the local built wheel.
See ~/spacer/test-harness/state/INSTALL_BLOCKER.md for details.
"""

import os
import sys
import time
from pathlib import Path

STATE = Path.home() / "spacer" / "test-harness" / "state"
DATA = Path.home() / "spacer" / "test-harness" / "ldk-data"
ESPLORA = "https://mutinynet.com/api"
LISTEN = "127.0.0.1:9735"
SYNC_TIMEOUT_SECS = 5 * 60

STATE.mkdir(parents=True, exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)


def _write(name: str, value: str) -> None:
    p = STATE / name
    p.write_text(value if value.endswith("\n") else value + "\n")
    print(f"wrote {p}")


def main() -> int:
    try:
        import ldk_node  # noqa: F401
        from ldk_node import (
            Builder,
            Network,
            NodeEntropy,
            default_config,
            generate_entropy_mnemonic,
        )
    except Exception as e:
        print(f"FATAL: cannot import ldk_node: {e}", file=sys.stderr)
        print("See ~/spacer/test-harness/state/INSTALL_BLOCKER.md", file=sys.stderr)
        return 2

    print("ldk_node imported OK; module attrs (truncated):")
    print(sorted(a for a in dir(ldk_node) if not a.startswith("_"))[:40])

    mnemonic = generate_entropy_mnemonic(None)
    # Persist mnemonic so we can reuse the same node identity across runs.
    mnemo_path = STATE / "ldk_mnemonic.txt"
    if mnemo_path.exists():
        mnemonic = mnemo_path.read_text().strip()
        print("reusing existing mnemonic")
    else:
        mnemo_path.write_text(str(mnemonic) + "\n")
        print(f"wrote new mnemonic to {mnemo_path}")

    node_entropy = NodeEntropy.from_bip39_mnemonic(mnemonic, None)

    config = default_config()
    builder = Builder.from_config(config)
    builder.set_storage_dir_path(str(DATA))
    builder.set_chain_source_esplora(ESPLORA, None)
    builder.set_network(Network.SIGNET)
    try:
        builder.set_listening_addresses([LISTEN])
    except Exception as e:
        print(f"could not set listening address ({e}); continuing without inbound")

    print("building node...")
    node = builder.build(node_entropy)

    print("starting node...")
    node.start()

    try:
        node_id = str(node.node_id())
        print("node_id:", node_id)
        _write("ldk_node_id.txt", node_id)

        listen = node.listening_addresses() or []
        _write("ldk_listen.txt", "\n".join(str(a) for a in listen) or "(none)")

        # Get a fresh on-chain receive address before sync so we don't block on it.
        addr = str(node.onchain_payment().new_address())
        print("address:", addr)
        _write("ldk_address.txt", addr)

        # Try to sync. Mutinynet is a 30s-block signet that's been running for years;
        # full sync from genesis can take a long time. There is no wallet-birthday
        # API in ldk-node yet (TODO upstream in builder.rs), so this is best-effort.
        print(f"syncing wallets (timeout {SYNC_TIMEOUT_SECS}s)...")
        t0 = time.time()
        try:
            node.sync_wallets()
            elapsed = time.time() - t0
            print(f"sync_wallets() returned after {elapsed:.1f}s")
            _write("ldk_sync_seconds.txt", f"{elapsed:.1f}")
        except Exception as e:
            elapsed = time.time() - t0
            print(f"sync failed after {elapsed:.1f}s: {e}")
            _write("ldk_sync_seconds.txt", f"FAILED after {elapsed:.1f}s: {e}")

        try:
            balances = node.list_balances()
            bal_line = (
                f"spendable_onchain={balances.spendable_onchain_balance_sats} "
                f"total_onchain={balances.total_onchain_balance_sats}"
            )
        except Exception as e:
            bal_line = f"ERROR reading balances: {e}"
        print("balance:", bal_line)
        _write("ldk_balance.txt", bal_line)

    finally:
        print("stopping node...")
        try:
            node.stop()
        except Exception as e:
            print(f"stop error (ignored): {e}")
        time.sleep(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
