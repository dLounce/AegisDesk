import aegisdesk


def test_package_is_importable_and_versioned() -> None:
    assert aegisdesk.__version__ == "0.0.1"
