from exsoftware.analyzers.strings import classify_string, extract_strings
from exsoftware.analyzers.entropy import shannon_entropy


def test_extracts_ascii_and_url():
    data = b"xxxxhttp://example.com/path yyyy"
    strings = extract_strings(data)
    values = [item["value"] for item in strings]
    assert any("http://example.com/path" in value for value in values)
    classified = classify_string("visit http://example.com/path now")
    assert classified["urls"]


def test_ipv4_and_interesting_pattern():
    classified = classify_string("powershell -enc AA== connect 203.0.113.50")
    assert "203.0.113.50" in classified["ips"]
    assert "powershell" in classified["interesting"]
    assert "encoded-command" in classified["interesting"]


def test_entropy_bounds():
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    high = shannon_entropy(bytes(range(256)) * 8)
    assert high > 7.5
