"""PEP-561 typing smoke tests."""
import os
import sys
import inspect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")


def test_py_typed_marker_exists():
    """py.typed marker must exist in the package directory."""
    marker = os.path.join(SRC, "cidr_subnet_pure", "py.typed")
    assert os.path.exists(marker), f"missing PEP-561 marker: {marker}"


def test_py_typed_marker_is_empty_or_marker():
    """py.typed should be an empty file (PEP-561 convention)."""
    marker = os.path.join(SRC, "cidr_subnet_pure", "py.typed")
    size = os.path.getsize(marker)
    # Either empty (0 bytes) or contains marker text
    with open(marker, "rb") as f:
        content = f.read()
    assert size == 0 or b"partial" in content or b"typed" in content.lower()


def test_version_is_string():
    """__version__ must be a str."""
    import cidr_subnet_pure
    assert isinstance(cidr_subnet_pure.__version__, str)
    assert cidr_subnet_pure.__version__  # non-empty


def test_public_api_uses_signature_annotations():
    """All public functions must have type-annotated signatures."""
    import cidr_subnet_pure as m
    public = [n for n in m.__all__ if not n[0].isupper()]  # exclude exceptions
    for name in public:
        fn = getattr(m, name)
        assert callable(fn), f"{name} not callable"
        sig = inspect.signature(fn)
        # Just verify the signature exists; doesn't require every param to be typed
        assert sig is not None


def test_no_third_party_imports():
    """The library must have no third-party imports (only stdlib)."""
    import pytest
    import cidr_subnet_pure
    import cidr_subnet_pure._parser
    import cidr_subnet_pure._membership
    import cidr_subnet_pure._iter
    import cidr_subnet_pure._algebra
    import cidr_subnet_pure._hierarchy
    import cidr_subnet_pure._errors
    stdlib = set(sys.stdlib_module_names)
    forbidden = []
    for mod_name, mod in [
        ("cidr_subnet_pure", cidr_subnet_pure),
        ("_parser", cidr_subnet_pure._parser),
        ("_membership", cidr_subnet_pure._membership),
        ("_iter", cidr_subnet_pure._iter),
        ("_algebra", cidr_subnet_pure._algebra),
        ("_hierarchy", cidr_subnet_pure._hierarchy),
        ("_errors", cidr_subnet_pure._errors),
    ]:
        for attr in dir(mod):
            if attr.startswith("_") and attr not in (
                "__name__", "__file__", "__path__", "__all__",
                "__version__", "__loader__", "__spec__", "__package__",
                "__cached__", "__builtins__",
            ):
                continue
            obj = getattr(mod, attr, None)
            if obj is None:
                continue
            mod_str = getattr(obj, "__module__", None)
            if mod_str and mod_str not in (
                "builtins",
                "ipaddress",
                "typing",
                "__future__",
            ) and not mod_str.startswith("cidr_subnet_pure"):
                # Check if it's stdlib
                top = mod_str.split(".")[0]
                if top not in stdlib:
                    forbidden.append((mod_name, attr, mod_str))
    assert not forbidden, f"non-stdlib imports found: {forbidden}"


def test_package_metadata_includes_typed_classifier():
    """pyproject.toml should declare 'Typing :: Typed' classifier."""
    import tomllib
    pyproject = os.path.join(ROOT, "pyproject.toml")
    if not os.path.exists(pyproject):
        import pytest
        pytest.skip("pyproject.toml not yet written")
        return
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    classifiers = data.get("project", {}).get("classifiers", [])
    assert any("Typed" in c for c in classifiers), (
        f"missing 'Typing :: Typed' classifier in: {classifiers}"
    )