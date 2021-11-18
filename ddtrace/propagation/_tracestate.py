import string


_whitespace = set(string.whitespace)
_tracestate_key_start = set(string.ascii_lowercase + string.digits)
_tracestate_key_chars = set(string.ascii_lowercase + string.digits + "_-*/")
_tracestate_value_chars = set(string.printable) - set(",=") - _whitespace


def encode_tracestate_header(values):
    # type: (Dict[str, str]) -> str
    """Convert a dictionary of tag key/values into a tracestate compatible header

    https://www.w3.org/TR/trace-context/#tracestate-header

    The implementation provided here does not validate the keys and values.
    It is left to the caller of the API to ensure the keys and values match
    the specification.
    """
    header = ""
    for i, (key, value) in enumerate(values.items()):
        if i > 0:
            header += ","
        header += "{}={}".format(key, value)
    return header


def parse_tracestate_header(header):
    # type: (str) -> Dict[str, str]
    """Parse a tracestate compatible header value into a dictionary of tag key/values

    https://www.w3.org/TR/trace-context/#tracestate-header

    Example::

        vendorname1=opaqueValue1,vendorname2=opaqueValue2

    Grammar::

        list  = list-member 0*31( OWS "," OWS list-member )
        list-member = key "=" value
        list-member = OWS
        key = lcalpha 0*255( lcalpha / DIGIT / "_" / "-"/ "*" / "/" )
        key = ( lcalpha / DIGIT ) 0*240( lcalpha / DIGIT / "_" / "-"/ "*" / "/" ) "@" lcalpha 0*13( lcalpha / DIGIT / "_" / "-"/ "*" / "/" )
        lcalpha    = %x61-7A ; a-z
        value    = 0*255(chr) nblk-chr
        nblk-chr = %x21-2B / %x2D-3C / %x3E-7E
        chr      = %x20 / nblk-chr

    The ``OWS`` rule defines an optional whitespace character. To improve readability,
    it is used where zero or more whitespace characters might appear.

    Identifiers MUST begin with a lowercase letter or a digit, and can only contain
    lowercase letters (a-z), digits (0-9), underscores (_), dashes (-), asterisks (*),
    and forward slashes (/)

    For multi-tenant vendor scenarios, an at sign (@) can be used to prefix the vendor name.
    Vendors SHOULD set the tenant ID at the beginning of the key. For example, fw529a3039@dt -
    fw529a3039 is a tenant ID and @dt is a vendor name. Searching for @dt= is more robust
    for parsing (for example, searching for all a vendor's keys).

    The value is an opaque string containing up to 256 printable ASCII [RFC0020] characters
    (i.e., the range 0x20 to 0x7E) except comma (,) and (=). Note that this also excludes
    tabs, newlines, carriage returns, etc.
    """
    res = {}
    if not header:
        return res

    buf = ""
    cur_key = None
    has_at = False
    for c in header:
        # Ignore spaces
        if c == " ":
            # TODO: Raise error if we are in the middle of a key or value ?
            continue
        elif c in _whitespace:
            raise ValueError("Malformed header tag: disallowed character {!r}, {!r}".format(c, header))

        # Key value separator
        elif c == "=":
            # Check if we have already had an "=", e.g. "key=value="
            if cur_key:
                raise ValueError("Malformed header tag: unexpected '=', {!r}".format(header))

            # Store the key, reset has_at, and start saving the value
            cur_key, has_at, buf = buf, False, ""

            # Check if we have "=value" (no key is set)
            if not cur_key:
                raise ValueError("Malformed header tag: empty key, {!r}".format(header))

        # Tag pair separators
        elif c == ",":
            # Ignore if we don't have a key or value, "," (no tag pair present)
            if not cur_key and not buf:
                continue

            # Check if we have "key," or "key=,", (no value set)
            if not cur_key or not buf:
                raise ValueError(
                    "Malformed header tag: ',' separator missing key or value ({!r}={!r}), {!r}".format(
                        cur_key, buf, header
                    )
                )
            res[cur_key] = buf
            cur_key, buf = None, ""

        # Check if we should append this character
        else:
            # We are parsing a key
            if not cur_key:
                # Key start
                if not buf:
                    if c not in _tracestate_key_start:
                        raise ValueError(
                            "Malformed header tag: key must start with 'a-z0-9' got {!r}, {!r}".format(c, header)
                        )
                # Check for '@'
                elif c == "@":
                    if has_at:
                        raise ValueError("Malformed header tag: key cannot contain multiple '@', {!r}".format(header))
                    has_at = True
                # After the '@' can only contain 'a-z'
                elif has_at:
                    if c not in string.ascii_lowercase:
                        raise ValueError(
                            "Malformed header tag: key can only contain 'a-z' in vendor name, {!r}".format(header)
                        )

                elif c not in _tracestate_key_chars:
                    raise ValueError(
                        "Malformed header tag: key must only contain 'a-z0-9_-*/' got {!r}, {!r}".format(c, header)
                    )

            # We are parsing a value
            else:
                if c not in _tracestate_value_chars:
                    raise ValueError("Malformed header tag: value contains invalid char {!r}, {!r}".format(c, header))

            # Passed all the checks, append the character
            buf += c

    # Reached the end and we have a key and a value, append them
    if buf and cur_key:
        res[cur_key] = buf

    # We reached the end and we have a key but no value "key="
    elif cur_key and not buf:
        raise ValueError("Malformed header tag: missing value for {!r}, {!r}".format(cur_key, header))

    # We have data in the buffer but no key ("key=value,bad-data")
    elif buf and not cur_key:
        raise ValueError("Malformed header tag: trailing data {!r}, {!r}".format(buf, header))

    return res
