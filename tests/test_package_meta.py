"""Tests for package metadata consistency — version sync, public API, py.typed."""

import pathlib

import agentguard


def test_version_is_string():
    assert isinstance(agentguard.__version__, str)


def test_version_matches_pyproject():
    """__version__ in __init__.py must match pyproject.toml."""
    root = pathlib.Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    assert pyproject.exists(), "pyproject.toml not found"

    for line in pyproject.read_text().splitlines():
        if line.strip().startswith("version"):
            # e.g. version = "0.3.0"
            pyproject_version = line.split("=", 1)[1].strip().strip('"').strip("'")
            break
    else:
        raise AssertionError("No version field found in pyproject.toml")

    assert agentguard.__version__ == pyproject_version, (
        f"__init__.py says {agentguard.__version__!r}, "
        f"pyproject.toml says {pyproject_version!r}"
    )


def test_py_typed_marker_exists():
    """PEP 561: py.typed marker must exist for typed package consumers."""
    pkg_dir = pathlib.Path(agentguard.__file__).parent
    assert (pkg_dir / "py.typed").exists(), "py.typed marker missing"


def test_all_exports_importable():
    """Every name in __all__ must be importable from the top-level package."""
    for name in agentguard.__all__:
        obj = getattr(agentguard, name, None)
        assert obj is not None, f"agentguard.__all__ lists {name!r} but it is not importable"
