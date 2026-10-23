"""Run the tests without pytest (python tests/run_all.py). pytest -q works too."""
import importlib
import inspect
import os
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tests.conftest  # noqa: E402,F401  (sets env vars)


def main() -> int:
    passed = failed = 0
    for mod_name in ("tests.test_security", "tests.test_system"):
        mod = importlib.import_module(mod_name)
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if not name.startswith("test_"):
                continue
            kwargs = {}
            if "tmp_path" in inspect.signature(fn).parameters:
                kwargs["tmp_path"] = Path(tempfile.mkdtemp())
            try:
                fn(**kwargs)
                passed += 1
                print(f"PASS {mod_name}.{name}")
            except Exception:
                failed += 1
                print(f"FAIL {mod_name}.{name}")
                traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
