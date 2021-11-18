import pytest

from ddtrace.propagation._tracestate import encode_tracestate_header
from ddtrace.propagation._tracestate import parse_tracestate_header


@pytest.mark.parametrize(
    "header,expected",
    [
        # Normal single tag pair
        ("key=value", {"key": "value"}),
        # Starting with a digit
        ("1key=value", {"1key": "value"}),
        # Only a comma
        (",", {}),
        # Empty value
        ("", {}),
        # Extra trailing comma
        ("key=value,", {"key": "value"}),
        # Leading and trailing extra commas without tag pairs
        (",key=value,,", {"key": "value"}),
        # Multiple values
        ("a=1,b=2,c=3", {"a": "1", "b": "2", "c": "3"}),
        # spaces and tabs are ignored
        ("  key = value , ", {"key": "value"}),
        # tenant@vendor format key
        ("tenant@vendor=value", {"tenant@vendor": "value"}),
    ],
)
def test_parse_tracestate_header(header, expected):
    """Test that provided header value is parsed as expected"""
    assert expected == parse_tracestate_header(header)


@pytest.mark.parametrize(
    "header",
    [
        "key",
        "key=",
        "key=,",
        "=",
        ",=,",
        ",=value",
        "key=value=value",
        "key=value,=value",
        "key=value,value",
        # Disallowed whitespace characters
        "key=value\r\n",
        "key\t=value\r\n",
        # Disallowed starting key characters
        "_key=value",
        # Disallow multiple '@' in the key
        "tenant@vendor@vendor=value",
        # Disallow non-ascii after '@' in key
        "tenant@vendor5=value",
    ],
)
def test_parse_tracestate_header_malformed(header):
    """Test that the provided malformed header values raise an exception"""
    with pytest.raises(ValueError):
        parse_tracestate_header(header)


@pytest.mark.parametrize(
    "values,expected",
    [
        # No values
        ({}, ""),
        # Single key/value
        ({"key": "value"}, "key=value"),
        # Multiple key/values
        ({"a": "1", "b": "2", "c": "3"}, "a=1,b=2,c=3"),
    ],
)
def test_encode_tracestate_header(values, expected):
    header = encode_tracestate_header(values)
    assert expected == header

    # Ensure what we generate also parses correctly
    assert values == parse_tracestate_header(header)
