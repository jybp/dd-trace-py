from typing import Dict
from typing import FrozenSet
from typing import Optional

from ..context import Context
from ..internal.logger import get_logger
from .utils import get_wsgi_header


log = get_logger(__name__)

# HTTP headers one should set for distributed tracing.
# These are cross-language (eg: Python, Go and other implementations should honor these)
HTTP_HEADER_TRACE_ID = "x-datadog-trace-id"
HTTP_HEADER_PARENT_ID = "x-datadog-parent-id"
HTTP_HEADER_SAMPLING_PRIORITY = "x-datadog-sampling-priority"
HTTP_HEADER_ORIGIN = "x-datadog-origin"
HTTP_HEADER_TAGS = "x-datadog-tags"


# Note that due to WSGI spec we have to also check for uppercased and prefixed
# versions of these headers
POSSIBLE_HTTP_HEADER_TRACE_IDS = frozenset([HTTP_HEADER_TRACE_ID, get_wsgi_header(HTTP_HEADER_TRACE_ID).lower()])
POSSIBLE_HTTP_HEADER_PARENT_IDS = frozenset([HTTP_HEADER_PARENT_ID, get_wsgi_header(HTTP_HEADER_PARENT_ID).lower()])
POSSIBLE_HTTP_HEADER_SAMPLING_PRIORITIES = frozenset(
    [HTTP_HEADER_SAMPLING_PRIORITY, get_wsgi_header(HTTP_HEADER_SAMPLING_PRIORITY).lower()]
)
POSSIBLE_HTTP_HEADER_ORIGIN = frozenset([HTTP_HEADER_ORIGIN, get_wsgi_header(HTTP_HEADER_ORIGIN).lower()])
POSSIBLE_HTTP_HEADER_TAGS = frozenset([HTTP_HEADER_TAGS, get_wsgi_header(HTTP_HEADER_TAGS).lower()])


def _parse_dd_tags_header(header):
    # type: (str) -> Dict[str, str]
    res = {}
    if not header:
        return res

    buf = ""
    cur_key = None
    for c in header:
        if c == "=":
            cur_key, buf = buf, ""
            # Check if we have "=value" (no key is set)
            if not cur_key:
                raise Exception("Malformed header tag: empty key, %r".format(header))
        elif c == ",":
            # Check if we have "key," "key=,", or "," (no value set, or no tag pair)
            if not cur_key or not buf:
                raise Exception(
                    "Malformed header tag: ',' separator missing key or value (%r=%r), %r".format(cur_key, buf, header)
                )
            res[cur_key] = buf
            cur_key, buf = None, ""
        else:
            # TODO: Any characters that shouldn't be allowed or we allow to escape?
            buf += c

    # Reached the end and we have a key and a value, append them
    if buf and cur_key:
        res[cur_key] = buf

    # We reached the end and we have a key but no value "key="
    elif cur_key and not buf:
        raise Exception("Malformed header tag: missing value for %r, %r".format(cur_key, header))

    # We have data in the buffer but no key ("key=value,bad-data")
    elif buf and not cur_key:
        raise Exception("Malformed header tag: trailing data %r, %r".format(buf, header))

    return res


class HTTPPropagator(object):
    """A HTTP Propagator using HTTP headers as carrier."""

    @staticmethod
    def inject(span_context, headers):
        # type: (Context, Dict[str, str]) -> None
        """Inject Context attributes that have to be propagated as HTTP headers.

        Here is an example using `requests`::

            import requests
            from ddtrace.propagation.http import HTTPPropagator

            def parent_call():
                with tracer.trace('parent_span') as span:
                    headers = {}
                    HTTPPropagator.inject(span.context, headers)
                    url = '<some RPC endpoint>'
                    r = requests.get(url, headers=headers)

        :param Context span_context: Span context to propagate.
        :param dict headers: HTTP headers to extend with tracing attributes.
        """
        headers[HTTP_HEADER_TRACE_ID] = str(span_context.trace_id)
        headers[HTTP_HEADER_PARENT_ID] = str(span_context.span_id)
        sampling_priority = span_context.sampling_priority
        # Propagate priority only if defined
        if sampling_priority is not None:
            headers[HTTP_HEADER_SAMPLING_PRIORITY] = str(span_context.sampling_priority)
        # Propagate origin only if defined
        if span_context.dd_origin is not None:
            headers[HTTP_HEADER_ORIGIN] = str(span_context.dd_origin)

    @staticmethod
    def _extract_header_value(possible_header_names, headers, default=None):
        # type: (FrozenSet[str], Dict[str, str], Optional[str]) -> Optional[str]
        for header in possible_header_names:
            try:
                return headers[header]
            except KeyError:
                pass

        return default

    @staticmethod
    def extract(headers):
        # type: (Dict[str,str]) -> Context
        """Extract a Context from HTTP headers into a new Context.

        Here is an example from a web endpoint::

            from ddtrace.propagation.http import HTTPPropagator

            def my_controller(url, headers):
                context = HTTPPropagator.extract(headers)
                if context:
                    tracer.context_provider.activate(context)

                with tracer.trace('my_controller') as span:
                    span.set_meta('http.url', url)

        :param dict headers: HTTP headers to extract tracing attributes.
        :return: New `Context` with propagated attributes.
        """
        if not headers:
            return Context()

        try:
            normalized_headers = {name.lower(): v for name, v in headers.items()}
            # TODO: Fix variable type changing (mypy)
            trace_id = HTTPPropagator._extract_header_value(
                POSSIBLE_HTTP_HEADER_TRACE_IDS,
                normalized_headers,
            )
            if trace_id is None:
                return Context()

            parent_span_id = HTTPPropagator._extract_header_value(
                POSSIBLE_HTTP_HEADER_PARENT_IDS,
                normalized_headers,
                default="0",
            )
            sampling_priority = HTTPPropagator._extract_header_value(
                POSSIBLE_HTTP_HEADER_SAMPLING_PRIORITIES,
                normalized_headers,
            )
            origin = HTTPPropagator._extract_header_value(
                POSSIBLE_HTTP_HEADER_ORIGIN,
                normalized_headers,
            )

            # Try to parse values into their expected types
            try:
                if sampling_priority is not None:
                    sampling_priority = int(sampling_priority)  # type: ignore[assignment]
                else:
                    sampling_priority = sampling_priority

                return Context(
                    # DEV: Do not allow `0` for trace id or span id, use None instead
                    trace_id=int(trace_id) or None,
                    span_id=int(parent_span_id) or None,  # type: ignore[arg-type]
                    sampling_priority=sampling_priority,  # type: ignore[arg-type]
                    dd_origin=origin,
                )
            # If headers are invalid and cannot be parsed, return a new context and log the issue.
            except (TypeError, ValueError):
                log.debug(
                    "received invalid x-datadog-* headers, trace-id: %r, parent-id: %r, priority: %r, origin: %r",
                    trace_id,
                    parent_span_id,
                    sampling_priority,
                    origin,
                )
                return Context()
        except Exception:
            log.debug("error while extracting x-datadog-* headers", exc_info=True)
            return Context()
