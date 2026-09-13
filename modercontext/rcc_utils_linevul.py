from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

LANGUAGE_LABELS = ["c", "cpp", "java", "python", "go", "other"]
LANGUAGE_TO_ID = {name: i for i, name in enumerate(LANGUAGE_LABELS)}

DATASET_LABELS = ["primevul", "bigvul", "other"]
DATASET_TO_ID = {name: i for i, name in enumerate(DATASET_LABELS)}

VULN_PIVOTS = [
    "missing_null_guard",
    "missing_bounds_guard",
    "unchecked_return_value",
    "missing_auth_or_state_guard",
    "cleanup_or_lifecycle_gap",
    "size_validation_gap",
    "missing_sanitization",
    "contract_mismatch",
    "unsafe_boundary_condition",
    "unknown",
]

SAFE_PIVOTS = [
    "present_null_guard",
    "present_bounds_guard",
    "present_return_guard",
    "present_auth_or_state_guard",
    "present_lifecycle_guard",
    "present_sanitization_guard",
    "no_dangerous_sink",
    "no_untrusted_flow_to_sink",
    "local_only_computation",
    "read_only_or_observer_path",
    "guard_not_required_for_this_path",
    "risk_not_triggered",
    "unknown",
]

PIVOT_TYPES = VULN_PIVOTS + [p for p in SAFE_PIVOTS if p not in VULN_PIVOTS]
FIX_SCOPE_VALUES = ["local", "path", "interface", "state", "architectural"]

COPY_APIS = ["memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "bcopy"]
FORMAT_APIS = ["sprintf", "snprintf", "vsprintf", "vsnprintf", "printf", "fprintf", "syslog"]
ALLOC_APIS = ["malloc", "calloc", "realloc", "new"]
FREE_APIS = ["free", "delete", "close", "fclose", "release", "destroy"]
LOCK_APIS = ["spin_lock", "mutex_lock", "pthread_mutex_lock", "lock", "acquire"]
UNLOCK_APIS = ["spin_unlock", "mutex_unlock", "pthread_mutex_unlock", "unlock", "release_lock"]
READ_APIS = ["read", "recv", "recvfrom", "fgets", "gets", "scanf", "sscanf", "fread"]
WRITE_APIS = ["write", "send", "sendto", "fprintf", "fwrite"]
CMD_APIS = ["system", "exec", "execl", "execv", "popen"]
PATH_APIS = ["open", "fopen", "stat", "unlink", "rename", "remove", "mkdir", "chdir"]
SANITIZE_MARKERS = ["sanitize", "escape", "validate", "checked", "check", "guard", "canonical"]
AUTH_MARKERS = ["auth", "token", "session", "permission", "credential", "role", "acl", "capability"]
STATE_MARKERS = ["state", "init", "initialized", "valid", "ready", "enabled", "disabled", "connected"]
NETWORK_MARKERS = ["socket", "recv", "send", "packet", "request", "http", "tcp", "udp"]
SIZE_MARKERS = ["size", "len", "count", "capacity", "sizeof", "strlen"]
STRING_MARKERS = ["str", "char *", "char*", "string", "strlen(", "strcpy(", "strncpy(", "sprintf("]
PATH_MARKERS = ["path", "file", "dir", "open(", "fopen(", "unlink(", "rename(", "mkdir("]

GENERIC_SAFE_CAUSAL = "The current path remains safe because the relevant risky condition is blocked or does not arise on this path."
GENERIC_VULN_CAUSAL = "The current path is unsafe because the decision-critical safeguard is missing on a risky path."


def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return int(default)


def normalize_dataset_name(name: Optional[str]) -> str:
    name = (name or "primevul").strip().lower()
    if "prime" in name:
        return "primevul"
    if "big" in name:
        return "bigvul"
    return "other"


def dataset_token(name: str) -> str:
    return normalize_dataset_name(name).upper()


def dataset_id(name: str) -> int:
    return DATASET_TO_ID.get(normalize_dataset_name(name), DATASET_TO_ID["other"])


def normalize_language_name(value: Optional[str], code: str = "") -> str:
    value = (value or "").strip().lower()
    if value in {"c", "c99", "c11"}:
        return "c"
    if value in {"c++", "cpp", "cxx", "cc"}:
        return "cpp"
    if value == "java":
        return "java"
    if value in {"python", "py"}:
        return "python"
    if value in {"go", "golang"}:
        return "go"

    code = code or ""
    code_low = code.lower()

    if "public class " in code_low or ("class " in code_low and "public static void main" in code_low):
        return "java"
    if re.search(r"(?m)^\s*def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", code_low):
        return "python"
    if re.search(r"(?m)^\s*func\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", code_low):
        return "go"

    cpp_markers = [
        "std::", "namespace ", "template<", "template <", "typename", "nullptr",
        "virtual ", "public:", "private:", "protected:", "using namespace",
        "dynamic_cast<", "static_cast<", "reinterpret_cast<", "const_cast<",
        "throw ", "catch(", "catch (", "try {", "operator<<", "operator>>",
    ]
    cpp_score = sum(tok in code_low for tok in cpp_markers)
    if "::" in code_low:
        cpp_score += 2
    if re.search(r"\b(class|template)\b", code_low):
        cpp_score += 1
    if re.search(r"\bnew\s+[A-Za-z_(]", code_low) or re.search(r"\bdelete\s+", code_low):
        cpp_score += 1
    if re.search(r"~[A-Za-z_][A-Za-z0-9_]*\s*\(", code):
        cpp_score += 2
    if re.search(r"\boperator\s*(\[\]|\(\)|[+\-*/%<>=!&|^~]+)\s*\(", code):
        cpp_score += 2
    if cpp_score >= 2:
        return "cpp"

    c_markers = [
        "#include", "->", "malloc(", "calloc(", "realloc(", "free(", "sizeof(",
        "size_t", "ssize_t", " struct ", "typedef ", "typedef struct", "enum ",
        "union ", "goto ", "char *", "char*", "void *", "void*", "uint32_t",
        "uint64_t", "int32_t", "int64_t", "kmalloc(", "kfree(", "g_free(",
        "spin_lock(", "spin_unlock(", "mutex_lock(", "mutex_unlock(", "#define",
        "#ifdef", "#ifndef", "#endif",
    ]
    c_score = sum(tok in code_low for tok in c_markers)
    if re.search(r"\bstruct\s+[A-Za-z_][A-Za-z0-9_]*\b", code_low):
        c_score += 1
    if re.search(r"\b(static|inline|extern)\b", code_low) and re.search(r"\b(return|goto|switch|if|for|while)\b", code_low):
        c_score += 1
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*->\s*[A-Za-z_][A-Za-z0-9_]*", code):
        c_score += 1
    if c_score >= 2:
        return "c"

    looks_c_family = (
        "{" in code_low and "}" in code_low and ";" in code_low and
        re.search(r"\b(if|for|while|switch|return)\b", code_low)
    )
    if looks_c_family:
        if "::" in code_low or re.search(r"\b(class|template|typename)\b", code_low):
            return "cpp"
        return "c"

    return "other"


def language_token(name: str) -> str:
    return normalize_language_name(name).upper()


def language_id(name: str) -> int:
    return LANGUAGE_TO_ID.get(normalize_language_name(name), LANGUAGE_TO_ID["other"])


def find_code_field(row: Dict[str, Any]) -> str:
    for key in ["code", "code_raw", "func", "function", "processed_func", "source", "code_before", "before_func", "func_before"]:
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def find_label_field(row: Dict[str, Any]) -> int:
    for key in ["y", "label", "target", "vul", "vulnerable", "is_vuln", "is_vulnerable"]:
        if key in row:
            return 1 if safe_int(row.get(key), 0) == 1 else 0
    return 0


def find_idx_field(row: Dict[str, Any], fallback_idx: int) -> int:
    for key in ["idx", "id", "sample_id", "example_id"]:
        if key in row:
            return safe_int(row.get(key), fallback_idx)
    return int(fallback_idx)


def _strip_comments_for_signature_scan(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    code = re.sub(r"//.*?$", " ", code, flags=re.MULTILINE)
    return code


def _normalize_candidate_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "unknown_fn"
    name = re.sub(r"\s+", " ", name)
    name = name.rstrip("{").strip()
    if "::" in name:
        name = name.split("::")[-1].strip()
    return name[:128] if name else "unknown_fn"


def find_function_name(row: Dict[str, Any], code: str = "") -> str:
    for key in ["function_name", "func_name", "name", "method_name", "signature"]:
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            return _normalize_candidate_name(val)

    code = code or ""
    scan = _strip_comments_for_signature_scan(code)
    head = scan.split("{", 1)[0] if "{" in scan else scan
    head = "\n".join(head.splitlines()[:40])

    patterns = [
        r"(?m)([A-Za-z_~][A-Za-z0-9_~<>]*::(?:~?[A-Za-z_][A-Za-z0-9_]*|operator\s*(?:\[\]|\(\)|[^\s(]+)))\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:\{|$)",
        r"(?m)\b(operator\s*(?:\[\]|\(\)|[^\s(]+))\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:\{|$)",
        r"(?m)\b(~?[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:\{|$)",
    ]
    for pat in patterns:
        m = re.search(pat, head)
        if m:
            cand = _normalize_candidate_name(m.group(1))
            if cand and cand != "unknown_fn":
                return cand

    m = re.search(r"(?m)\b(~?[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}\n]{0,300}\)\s*(?:\{|$)", scan)
    if m:
        return _normalize_candidate_name(m.group(1))

    return "unknown_fn"


def _word_boundary_hits(text: str, terms: Sequence[str]) -> List[str]:
    out: List[str] = []
    for t in terms:
        if re.search(rf"\b{re.escape(t)}\b", text):
            out.append(t)
    return sorted(set(out))


def _call_name_hits(text: str) -> List[str]:
    return re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)


def _line_indices_for_terms(lines: Sequence[str], terms: Sequence[str]) -> List[int]:
    idxs: List[int] = []
    for i, line in enumerate(lines):
        low = line.lower()
        if any(t in low for t in terms):
            idxs.append(i)
    return sorted(set(idxs))


def _line_indices_for_regex(lines: Sequence[str], patterns: Sequence[str]) -> List[int]:
    idxs: List[int] = []
    compiled = [re.compile(p) for p in patterns]
    for i, line in enumerate(lines):
        if any(p.search(line) for p in compiled):
            idxs.append(i)
    return sorted(set(idxs))


def _count_max_nesting(lines: Sequence[str]) -> int:
    nesting = 0
    max_nesting = 0
    for line in lines:
        nesting += line.count("{")
        max_nesting = max(max_nesting, nesting)
        nesting -= line.count("}")
        nesting = max(nesting, 0)
    return max_nesting


def _bucket_count(n: int) -> str:
    if n <= 0:
        return "0"
    if n == 1:
        return "1"
    if n == 2:
        return "2"
    if n == 3:
        return "3"
    if n == 4:
        return "4"
    return "5plus"


def _bucket_count_3(n: int) -> str:
    if n <= 0:
        return "0"
    if n == 1:
        return "1"
    if n == 2:
        return "2"
    return "3plus"


def _bool_str(v: bool) -> str:
    return "yes" if bool(v) else "no"


def _trim_lines_around(lines: Sequence[str], indices: Sequence[int], window: int = 2) -> List[str]:
    chosen = set()
    for idx in indices:
        for j in range(max(0, idx - window), min(len(lines), idx + window + 1)):
            chosen.add(j)
    return [lines[i] for i in sorted(chosen)]


def _token_len(tokenizer: Any, text: str) -> int:
    if not text:
        return 0
    try:
        return len(tokenizer(text, add_special_tokens=False)["input_ids"])
    except Exception:
        return max(1, len(text) // 4)


def extract_maximal_features(code: str, function_name: str = "unknown_fn", language_name: str = "other") -> Dict[str, Any]:
    code = code or ""
    lines = code.splitlines() or [code]
    low = code.lower()
    fn_low = (function_name or "unknown_fn").lower()
    call_region = code.split("{", 1)[1] if "{" in code else code
    call_names = [c.lower() for c in _call_name_hits(call_region) if c.lower() != fn_low]

    copy_hits = _word_boundary_hits(low, COPY_APIS)
    format_hits = _word_boundary_hits(low, FORMAT_APIS)
    alloc_hits = _word_boundary_hits(low, ALLOC_APIS)
    free_hits = _word_boundary_hits(low, FREE_APIS)
    lock_hits = _word_boundary_hits(low, LOCK_APIS)
    unlock_hits = _word_boundary_hits(low, UNLOCK_APIS)
    read_hits = _word_boundary_hits(low, READ_APIS)
    write_hits = _word_boundary_hits(low, WRITE_APIS)
    cmd_hits = _word_boundary_hits(low, CMD_APIS)
    path_hits = _word_boundary_hits(low, PATH_APIS)
    auth_hits = _word_boundary_hits(low, AUTH_MARKERS)
    state_hits = _word_boundary_hits(low, STATE_MARKERS)
    sanitize_hits = _word_boundary_hits(low, SANITIZE_MARKERS)

    free_like_hits = sorted({c for c in call_names if re.search(r"(?:^|_)(free|close|release|destroy)(?:$|_)", c)})
    alloc_like_hits = sorted({c for c in call_names if re.search(r"(?:^|_)(alloc|create|new|malloc|calloc|realloc)(?:$|_)", c)})
    if free_like_hits:
        free_hits = sorted(set(free_hits + free_like_hits))
    if alloc_like_hits:
        alloc_hits = sorted(set(alloc_hits + alloc_like_hits))

    has_pointer_deref = "->" in code or bool(re.search(r"\*\s*[A-Za-z_][A-Za-z0-9_]*", code))
    has_array_index = "[" in code and "]" in code
    has_pointer_arith = bool(re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*[\+\-]\s*\d+", code)) or "++" in code or "--" in code
    has_size_calc = any(tok in low for tok in ["sizeof(", "strlen(", "len", "size", "count", "capacity"])
    has_shift = "<<" in code or ">>" in code
    has_signed_unsigned_mix = "size_t" in code and re.search(r"\bint\b", code) is not None
    has_narrowing_cast = bool(re.search(r"\((int|short|char)\)\s*[A-Za-z_][A-Za-z0-9_]*", code))
    has_widening_cast = bool(re.search(r"\((long|size_t|unsigned long)\)\s*[A-Za-z_][A-Za-z0-9_]*", code))

    if_lines = _line_indices_for_regex(lines, [r"\bif\s*\("])
    switch_lines = _line_indices_for_regex(lines, [r"\bswitch\s*\("])
    for_lines = _line_indices_for_regex(lines, [r"\bfor\s*\("])
    while_lines = _line_indices_for_regex(lines, [r"\bwhile\s*\("])
    goto_lines = _line_indices_for_regex(lines, [r"\bgoto\b"])
    return_lines = _line_indices_for_regex(lines, [r"\breturn\b"])
    cleanup_label_lines = _line_indices_for_regex(lines, [r"\bcleanup\s*:", r"\berr(or)?\s*:", r"\bout\s*:"])

    has_null_if_check = bool(re.search(r"\bif\s*\([^)]*(?:!\s*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*(?:==|!=)\s*(?:null|nullptr|0)|(?:null|nullptr|0)\s*(?:==|!=)\s*[A-Za-z_][A-Za-z0-9_]*)", low))
    has_null_assert = bool(re.search(r"\bassert\s*\([^)]*(?:!\s*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*(?:==|!=)\s*(?:null|nullptr|0)|(?:null|nullptr|0)\s*(?:==|!=)\s*[A-Za-z_][A-Za-z0-9_]*)", low))
    has_null_check = has_null_if_check or has_null_assert
    has_bounds_check = bool(re.search(r"\bif\s*\([^)]*(<|<=|>|>=)[^)]*(len|size|count|capacity|sizeof|strlen|index)\b", low))
    has_return_check = bool(re.search(r"\bif\s*\([^)]*\b(?:status|retval|rc|err|errno|ret)\b(?:\s*(?:[!=<>)]|&&|\|\|)|$)", low))
    has_auth_check = bool(auth_hits) and bool(re.search(r"\bif\s*\(", low))
    has_state_check = bool(state_hits) and bool(re.search(r"\bif\s*\(", low))
    has_overflow_check = bool(re.search(r"\bif\s*\([^)]*(overflow|max|min|size)\b", low))
    has_size_match_check = bool(re.search(r"\bif\s*\([^)]*(len|size|count)[^)]*(==|!=|<=|>=|<|>)", low))
    has_capacity_check = bool(re.search(r"\bif\s*\([^)]*capacity\b", low))
    has_sanitizer = bool(sanitize_hits)

    arg_list_match = re.search(r"\((.*?)\)", code.split("{", 1)[0], flags=re.DOTALL)
    param_count = 0
    param_sig = ""
    if arg_list_match:
        param_sig = arg_list_match.group(1).strip()
        if param_sig and param_sig not in {"void"}:
            param_count = len([x for x in param_sig.split(",") if x.strip()])
    pointer_param_likely = "*" in param_sig or "[" in param_sig

    fn_kind = "unknown"
    if any(tok in fn_low for tok in ["parse", "decode", "load"]):
        fn_kind = "parser"
    elif any(tok in fn_low for tok in ["validate", "check", "guard"]):
        fn_kind = "validator"
    elif any(tok in fn_low for tok in ["alloc", "create", "new"]):
        fn_kind = "allocator"
    elif any(tok in fn_low for tok in ["free", "destroy", "release", "cleanup", "close"]):
        fn_kind = "cleanup"
    elif any(tok in fn_low for tok in ["auth", "login", "acl", "perm"]):
        fn_kind = "auth"
    elif lock_hits or unlock_hits:
        fn_kind = "sync"
    elif read_hits or write_hits or path_hits:
        fn_kind = "io"
    elif copy_hits or alloc_hits or free_hits:
        fn_kind = "memory"
    else:
        fn_kind = "utility"

    visibility = "local"
    first_nonempty = next((ln.strip() for ln in lines if ln.strip()), "")
    if first_nonempty.startswith("static "):
        visibility = "static"

    returns_pointer = "*" in first_nonempty.split("(")[0] or "char *" in first_nonempty or "void *" in first_nonempty
    returns_status = bool(re.search(r"\b(int|bool|status|errno)\b", first_nonempty.lower()))
    returns_length_like = bool(re.search(r"\b(size_t|ssize_t|length|len|size)\b", first_nonempty.lower()))

    src_file = bool(path_hits) or any(m in low for m in ["fopen", "fread", "open("])
    src_network = bool(_word_boundary_hits(low, NETWORK_MARKERS))
    src_socket = "socket" in low or "recv" in low or "send" in low
    src_ipc = any(tok in low for tok in ["ipc", "pipe", "shm", "mq_"])
    src_stdin = "stdin" in low
    src_deserialize = bool(_word_boundary_hits(low, ["json", "xml", "deserialize", "decode", "parse"]))
    src_env = "getenv" in low or "env" in low
    src_argv = "argv" in low
    src_global = "static " in code or bool(re.search(r"\bglobal\b", low))
    src_callee_return = bool(re.search(r"=\s*[A-Za-z_][A-Za-z0-9_]*\([^;]*\)", code))
    src_param = "pointer" if pointer_param_likely else ("scalar" if param_count > 0 else "none")
    if param_count > 1 and pointer_param_likely:
        src_param = "mixed"
    elif pointer_param_likely and any(tok in param_sig for tok in ["[]", "char *", "void *"]):
        src_param = "buffer"

    input_objects = []
    for name, cond in [
        ("buf", any(tok in low for tok in ["buf", "buffer"])),
        ("ptr", pointer_param_likely or has_pointer_deref),
        ("len", any(tok in low for tok in ["len", "length"])),
        ("idx", any(tok in low for tok in ["idx", "index"])),
        ("size", any(tok in low for tok in ["size", "sizeof"])),
        ("count", "count" in low),
        ("path", any(tok in low for tok in ["path", "file", "dir"])),
        ("fmt", any(tok in low for tok in ["fmt", "format", "printf", "sprintf"])),
        ("cmd", any(tok in low for tok in ["cmd", "system", "exec"])),
        ("fd", "fd" in low),
        ("state", any(tok in low for tok in STATE_MARKERS)),
        ("lock", bool(lock_hits or unlock_hits)),
        ("obj", "obj" in low or "this" in low),
    ]:
        if cond:
            input_objects.append(name)
    if not input_objects:
        input_objects = ["none"]

    sink_family: List[str] = []
    if copy_hits or alloc_hits or free_hits or has_pointer_deref or has_array_index:
        sink_family.append("memory")
    if copy_hits or format_hits:
        sink_family.append("string")
    if has_size_calc or has_shift or has_narrowing_cast or has_widening_cast:
        sink_family.append("integer")
    if alloc_hits or free_hits or path_hits:
        sink_family.append("resource")
    if lock_hits or unlock_hits:
        sink_family.append("sync")
    if read_hits or write_hits:
        sink_family.append("io")
    if cmd_hits:
        sink_family.append("command")
    if path_hits:
        sink_family.append("path")
    if format_hits:
        sink_family.append("format")
    if src_deserialize:
        sink_family.append("serialization")
    sink_family = sorted(set(sink_family)) or ["none"]

    sink_count = sum([
        len(copy_hits), len(format_hits), len(alloc_hits), len(free_hits), len(lock_hits), len(unlock_hits), len(read_hits), len(write_hits), len(cmd_hits), len(path_hits), int(has_pointer_deref), int(has_array_index), int(has_size_calc), int(has_shift),
    ])

    branch_count = len(if_lines) + len(switch_lines)
    max_nesting = _count_max_nesting(lines)
    multi_exit = len(return_lines) > 1

    cleanup_on_error = "none"
    if cleanup_label_lines or goto_lines:
        cleanup_on_error = "partial"
        if free_hits or unlock_hits or "close(" in low or "release(" in low:
            cleanup_on_error = "strong"

    contract_requires_nonnull = (has_pointer_deref or unlock_hits or copy_hits) and pointer_param_likely
    contract_requires_len = bool(copy_hits or has_array_index or has_size_calc)
    contract_requires_capacity = bool(copy_hits or format_hits)
    contract_requires_init = bool(any(tok in low for tok in ["init", "initialized", "ready"]))
    contract_requires_lock_held = bool(unlock_hits)
    contract_requires_auth = bool(auth_hits) and bool(cmd_hits or path_hits or write_hits or read_hits)
    contract_requires_state = bool(state_hits) or bool(unlock_hits or lock_hits)
    contract_ensures_release = bool(free_hits or unlock_hits or "close(" in low or "release(" in low)
    contract_ensures_nullterm = bool(format_hits or copy_hits)
    contract_ensures_bounds = bool(copy_hits or has_array_index)

    motif_missing_null_guard = (has_pointer_deref or unlock_hits or copy_hits) and not has_null_check
    motif_missing_bounds_guard = (copy_hits or has_array_index) and not has_bounds_check
    motif_unchecked_return = has_return_check is False and bool(re.search(r"=\s*[A-Za-z_][A-Za-z0-9_]*\([^;]*\)", code)) and (write_hits or free_hits or unlock_hits or path_hits or copy_hits)
    motif_missing_auth_gate = bool(auth_hits) and not has_auth_check and (cmd_hits or path_hits or write_hits)
    motif_missing_state_guard = bool(unlock_hits or lock_hits or _word_boundary_hits(low, STATE_MARKERS)) and not has_state_check
    motif_incomplete_cleanup = cleanup_on_error in {"none", "partial"} and (alloc_hits or lock_hits or unlock_hits)
    motif_len_to_copy_mismatch = bool(copy_hits) and has_size_calc and not has_bounds_check
    motif_return_value_ignored = motif_unchecked_return
    motif_unlock_without_existence_check = bool(unlock_hits) and has_pointer_deref and not has_null_check
    motif_global_state_dependency = src_global and bool(_word_boundary_hits(low, STATE_MARKERS))
    motif_untrusted_command = bool(cmd_hits and (src_network or src_file or src_param != "none") and not has_sanitizer)
    motif_untrusted_path = bool(path_hits and (src_network or src_file or src_param != "none") and not has_sanitizer)
    motif_input_to_copy = bool(copy_hits and (src_param != "none" or src_network or src_file))
    motif_input_to_index = bool(has_array_index and (src_param != "none" or src_network or src_file))
    motif_input_to_alloc = bool(alloc_hits and has_size_calc and (src_param != "none" or src_network or src_file))
    motif_check_after_use = bool(re.search(r"(\w+->\w+).*if\s*\(", code, flags=re.DOTALL))
    motif_use_without_null_guard = motif_missing_null_guard

    contract_mismatch_likely = "high" if ((contract_requires_nonnull and not has_null_check) or (contract_requires_len and not has_bounds_check) or (contract_requires_state and not has_state_check)) else ("med" if (contract_requires_nonnull or contract_requires_len or contract_requires_state) else "low")

    mem_copy_without_bound = bool(copy_hits and not has_bounds_check)
    mem_len_mismatch_risk = "high" if motif_len_to_copy_mismatch else ("med" if copy_hits and not has_bounds_check else "low")
    mem_null_deref_risk = "high" if motif_missing_null_guard else ("med" if has_pointer_deref else "low")
    mem_oob_read_risk = "high" if has_array_index and not has_bounds_check else "low"
    mem_oob_write_risk = "high" if (copy_hits or has_array_index) and not has_bounds_check else "low"
    mem_uaf_risk = "med" if free_hits and has_pointer_deref else "low"
    mem_double_free_risk = "med" if len(free_hits) > 0 and code.lower().count("free(") > 1 else "low"
    mem_leak_risk = "med" if alloc_hits and cleanup_on_error == "none" else "low"
    mem_uninit_read_risk = "med" if any(tok in low for tok in ["uninit", "initialize", "init"]) and not has_state_check else "low"
    mem_dangling_risk = "med" if free_hits and bool(re.search(r"\breturn\b.*\b[A-Za-z_][A-Za-z0-9_]*", code, flags=re.DOTALL)) else "low"

    int_truncation_risk = "high" if has_narrowing_cast else ("med" if has_signed_unsigned_mix else "low")
    str_truncation_possible = "med" if format_hits and not has_bounds_check else "low"
    str_format_string_risk = "high" if format_hits and not has_sanitizer else "low"
    str_path_traversal_risk = "high" if path_hits and (src_network or src_file or src_param != "none") and not has_sanitizer else "low"
    res_asymmetry_risk = "high" if motif_incomplete_cleanup else ("med" if alloc_hits or lock_hits or unlock_hits else "low")
    res_release_without_acquire = "med" if unlock_hits and not lock_hits else "low"
    res_missing_release = "med" if alloc_hits and cleanup_on_error == "none" else "low"
    err_inconsistent_error_path = "high" if goto_lines and cleanup_on_error == "none" else ("med" if goto_lines or cleanup_label_lines else "low")
    conc_race_risk = "med" if src_global and not (lock_hits or unlock_hits) else "low"
    conc_state_transition = "med" if (lock_hits or unlock_hits or _word_boundary_hits(low, STATE_MARKERS)) else "low"

    risk_memory = "high" if any(v == "high" for v in [mem_null_deref_risk, mem_oob_write_risk, mem_len_mismatch_risk]) else ("med" if any(v == "med" for v in [mem_null_deref_risk, mem_oob_write_risk, mem_len_mismatch_risk, mem_leak_risk]) else "low")
    risk_integer = "high" if int_truncation_risk == "high" else ("med" if has_size_calc or has_shift else "low")
    risk_resource = "high" if res_asymmetry_risk == "high" else ("med" if alloc_hits or lock_hits or unlock_hits else "low")
    risk_input = "high" if (src_network or src_file or src_param != "none") and (copy_hits or cmd_hits or path_hits) else ("med" if src_param != "none" or src_network or src_file else "low")
    risk_concurrency = "high" if conc_race_risk == "high" else ("med" if lock_hits or unlock_hits else "low")
    risk_contract = contract_mismatch_likely
    overall_high = sum(v == "high" for v in [risk_memory, risk_integer, risk_resource, risk_input, risk_concurrency, risk_contract])
    overall_med = sum(v == "med" for v in [risk_memory, risk_integer, risk_resource, risk_input, risk_concurrency, risk_contract])
    risk_overall = "high" if overall_high >= 2 else ("med" if overall_high >= 1 or overall_med >= 2 else "low")

    api_tokens = sorted(set((copy_hits + format_hits + alloc_hits + free_hits + lock_hits + unlock_hits + read_hits + write_hits + cmd_hits + path_hits)))[:6]
    if not api_tokens:
        api_tokens = ["none"]

    var_tokens = [name for name, cond in [
        ("buf", any(tok in low for tok in ["buf", "buffer"])),
        ("ptr", pointer_param_likely or has_pointer_deref),
        ("len", any(tok in low for tok in ["len", "length"])),
        ("idx", any(tok in low for tok in ["idx", "index"])),
        ("size", any(tok in low for tok in ["size", "sizeof"])),
        ("count", "count" in low),
        ("lock", bool(lock_hits or unlock_hits)),
        ("fd", "fd" in low),
        ("path", any(tok in low for tok in ["path", "file", "dir"])),
        ("fmt", any(tok in low for tok in ["fmt", "format"])),
        ("state", any(tok in low for tok in STATE_MARKERS)),
        ("obj", "obj" in low or "this" in low),
    ] if cond] or ["none"]

    check_tokens = []
    if has_null_check:
        check_tokens.append("if_null")
    if has_bounds_check:
        check_tokens.append("if_bounds")
    if has_state_check:
        check_tokens.append("if_state")
    if has_auth_check:
        check_tokens.append("if_auth")
    if has_return_check:
        check_tokens.append("if_ret")
    if not check_tokens:
        check_tokens = ["none"]

    evidence_line_indices = sorted(set(_line_indices_for_terms(lines, copy_hits + format_hits + alloc_hits + free_hits + lock_hits + unlock_hits + read_hits + write_hits + cmd_hits + path_hits) + _line_indices_for_regex(lines, [r"->", r"\[[^\]]+\]", r"\bif\s*\(", r"\bgoto\b", r"\breturn\b"])))
    path_site = "cleanup" if cleanup_label_lines else ("error" if goto_lines else ("mixed" if multi_exit else "main"))

    return {
        "schema_version": "secctx_v2_preproc",
        "lang": language_name,
        "role": {
            "fn_kind": fn_kind,
            "visibility": visibility,
            "returns_pointer": _bool_str(returns_pointer),
            "returns_status": _bool_str(returns_status),
            "returns_length_like": _bool_str(returns_length_like),
            "param_count_bucket": _bucket_count(param_count),
            "has_variadic": _bool_str("..." in param_sig),
        },
        "src": {
            "src_param": src_param,
            "src_argv": _bool_str(src_argv),
            "src_env": _bool_str(src_env),
            "src_file": _bool_str(src_file),
            "src_network": _bool_str(src_network),
            "src_socket": _bool_str(src_socket),
            "src_ipc": _bool_str(src_ipc),
            "src_stdin": _bool_str(src_stdin),
            "src_deserialize": _bool_str(src_deserialize),
            "src_global": _bool_str(src_global),
            "src_callee_return": _bool_str(src_callee_return),
            "src_user_controlled_likely": "high" if (src_network or src_file) else ("med" if src_param != "none" else "low"),
            "input_objects": sorted(set(input_objects)),
        },
        "sink": {
            "sink_family": sink_family,
            "sink_count_bucket": _bucket_count(sink_count),
            "sink_memcpy": _bool_str("memcpy" in copy_hits),
            "sink_memmove": _bool_str("memmove" in copy_hits),
            "sink_strcpy": _bool_str("strcpy" in copy_hits),
            "sink_strncpy": _bool_str("strncpy" in copy_hits),
            "sink_strcat": _bool_str("strcat" in copy_hits or "strncat" in copy_hits),
            "sink_sprintf": _bool_str("sprintf" in format_hits),
            "sink_snprintf": _bool_str("snprintf" in format_hits),
            "sink_printf_family": _bool_str(bool(format_hits)),
            "sink_malloc": _bool_str("malloc" in alloc_hits),
            "sink_calloc": _bool_str("calloc" in alloc_hits),
            "sink_realloc": _bool_str("realloc" in alloc_hits),
            "sink_free": _bool_str(bool(free_hits) and any((h == "free") or h.endswith("_free") or h.startswith("free_") or ("release" in h) or ("destroy" in h) for h in free_hits)),
            "sink_new_delete": _bool_str(("new" in alloc_hits) or ("delete" in free_hits) or any(h.endswith("_delete") or h.startswith("delete_") for h in free_hits)),
            "sink_open": _bool_str(any(x in path_hits for x in ["open", "fopen"])),
            "sink_close": _bool_str(any((h in {"close", "fclose"}) or h.endswith("_close") or h.startswith("close_") for h in free_hits)),
            "sink_read": _bool_str(bool(read_hits)),
            "sink_write": _bool_str(bool(write_hits)),
            "sink_exec": _bool_str(bool(cmd_hits)),
            "sink_system": _bool_str("system" in cmd_hits or "popen" in cmd_hits),
            "sink_sql": "no",
            "sink_xml": _bool_str("xml" in low),
            "sink_json_parse": _bool_str("json" in low),
            "sink_regex": _bool_str("regex" in low),
            "sink_lock": _bool_str(bool(lock_hits)),
            "sink_unlock": _bool_str(bool(unlock_hits)),
            "sink_atomic": _bool_str("atomic" in low),
            "sink_pointer_deref": _bool_str(has_pointer_deref),
            "sink_array_index": _bool_str(has_array_index),
            "sink_cast": _bool_str(bool(has_narrowing_cast or has_widening_cast)),
            "sink_arithmetic": _bool_str(bool(has_size_calc)),
            "sink_shift": _bool_str(bool(has_shift)),
        },
        "validate": {
            "check_null": "strong" if has_null_check else "none",
            "check_bounds": "strong" if has_bounds_check else "none",
            "check_len": "strong" if has_bounds_check and has_size_calc else ("partial" if has_size_calc else "none"),
            "check_range": "strong" if has_bounds_check else "none",
            "check_sign": "partial" if has_signed_unsigned_mix else "none",
            "check_overflow": "strong" if has_overflow_check else "none",
            "check_type": "partial" if has_narrowing_cast or has_widening_cast else "none",
            "check_enum": "none",
            "check_permission": "strong" if has_auth_check else "none",
            "check_auth": "strong" if has_auth_check else "none",
            "check_state": "strong" if has_state_check else "none",
            "check_return_code": "strong" if has_return_check else "none",
            "check_error_code": "strong" if has_return_check else "none",
            "check_lock_state": "strong" if has_state_check and (lock_hits or unlock_hits) else "none",
            "check_initialized": "strong" if has_state_check else "none",
            "check_size_match": "strong" if has_size_match_check else "none",
            "check_capacity": "strong" if has_capacity_check else "none",
            "sanitize_string": "strong" if has_sanitizer and bool(copy_hits or format_hits) else "none",
            "sanitize_path": "strong" if has_sanitizer and bool(path_hits) else "none",
            "sanitize_format": "strong" if has_sanitizer and bool(format_hits) else "none",
            "sanitize_command": "strong" if has_sanitizer and bool(cmd_hits) else "none",
            "sanitize_sql": "none",
            "guard_strength": "strong" if sum([has_null_check, has_bounds_check, has_return_check, has_auth_check, has_state_check, has_sanitizer]) >= 3 else ("partial" if sum([has_null_check, has_bounds_check, has_return_check, has_auth_check, has_state_check, has_sanitizer]) >= 1 else "none"),
        },
        "mem": {"mem_len_mismatch_risk": mem_len_mismatch_risk, "mem_null_deref_risk": mem_null_deref_risk, "mem_oob_write_risk": mem_oob_write_risk},
        "int": {"int_size_calc_for_alloc": _bool_str(bool(alloc_hits) and has_size_calc), "int_truncation_risk": int_truncation_risk},
        "str": {"str_format_string_risk": str_format_string_risk, "str_path_traversal_risk": str_path_traversal_risk},
        "res": {"res_cleanup_on_error": cleanup_on_error, "res_lock_release": _bool_str(bool(unlock_hits)), "res_alloc_cleanup_pattern": _bool_str(bool(alloc_hits and (free_hits or cleanup_on_error != "none")))},
        "err": {"err_ignored_callee_return": _bool_str(motif_unchecked_return)},
        "cf": {"cf_branch_count_bucket": _bucket_count(branch_count), "cf_max_nesting_bucket": _bucket_count(max_nesting)},
        "conc": {"conc_state_transition": conc_state_transition},
        "global": {"glob_state_dep": "high" if motif_global_state_dependency else ("med" if src_global else "low")},
        "call": {"uses_return_of_callee": "some" if src_callee_return else "none", "ignores_return_of_callee": "some" if motif_unchecked_return else "none"},
        "contract": {
            "contract_requires_nonnull": "yes" if contract_requires_nonnull else "no",
            "contract_requires_len": "yes" if contract_requires_len else "no",
            "contract_requires_capacity": "yes" if contract_requires_capacity else "no",
            "contract_requires_auth": "yes" if contract_requires_auth else "no",
            "contract_requires_state": "yes" if contract_requires_state else "no",
            "contract_ensures_release": "yes" if contract_ensures_release else "no",
            "contract_ensures_bounds": "yes" if contract_ensures_bounds else "no",
            "contract_mismatch_likely": contract_mismatch_likely,
        },
        "motif": {
            "motif_input_to_copy": _bool_str(motif_input_to_copy),
            "motif_input_to_index": _bool_str(motif_input_to_index),
            "motif_input_to_alloc": _bool_str(motif_input_to_alloc),
            "motif_len_to_copy_mismatch": _bool_str(motif_len_to_copy_mismatch),
            "motif_check_after_use": _bool_str(motif_check_after_use),
            "motif_use_without_null_guard": _bool_str(motif_use_without_null_guard),
            "motif_unlock_without_existence_check": _bool_str(motif_unlock_without_existence_check),
            "motif_missing_auth_gate": _bool_str(motif_missing_auth_gate),
            "motif_missing_state_guard": _bool_str(motif_missing_state_guard),
            "motif_untrusted_format": _bool_str(bool(format_hits and not has_sanitizer)),
            "motif_untrusted_path": _bool_str(motif_untrusted_path),
            "motif_untrusted_command": _bool_str(motif_untrusted_command),
            "motif_incomplete_cleanup": _bool_str(motif_incomplete_cleanup),
            "motif_return_value_ignored": _bool_str(motif_return_value_ignored),
            "motif_global_state_dependency": _bool_str(motif_global_state_dependency),
        },
        "evidence": {"api_tokens": api_tokens, "var_tokens": sorted(set(var_tokens)), "check_tokens": sorted(set(check_tokens)), "path_site": path_site, "line_indices": evidence_line_indices},
        "risk": {"risk_memory": risk_memory, "risk_integer": risk_integer, "risk_resource": risk_resource, "risk_input": risk_input, "risk_concurrency": risk_concurrency, "risk_contract": risk_contract, "risk_overall": risk_overall},
    }



def derive_pivot(profile: Dict[str, Any], label: Optional[int] = None) -> Dict[str, str]:
    """
    Derive a lightweight pivot from observable evidence only.

    The optional ``label`` argument is accepted for backward compatibility but is
    intentionally ignored so that no gold-label information can flow into the
    classifier input through pivot selection or summary generation.
    """
    motif = profile["motif"]
    validate = profile["validate"]
    contract = profile["contract"]
    res = profile["res"]
    sink = profile["sink"]
    risk = profile["risk"]
    src = profile["src"]
    role = profile["role"]
    integ = profile.get("int", {})

    low_risk = risk["risk_overall"] == "low"
    no_dangerous_sink = sink["sink_count_bucket"] == "0" or sink["sink_family"] == ["none"]
    no_untrusted_flow = src["src_user_controlled_likely"] == "low" and risk["risk_input"] == "low"

    low_effect_io_only = (
        sink["sink_read"] == "yes"
        and sink["sink_write"] == "no"
        and sink["sink_exec"] == "no"
        and sink["sink_system"] == "no"
        and sink["sink_open"] == "no"
        and sink["sink_memcpy"] == "no"
        and sink["sink_pointer_deref"] == "no"
        and sink["sink_array_index"] == "no"
    )
    local_only = (
        role["fn_kind"] in {"utility", "validator"}
        and low_risk
        and sink["sink_exec"] == "no"
        and sink["sink_system"] == "no"
        and sink["sink_write"] == "no"
        and sink["sink_open"] == "no"
        and sink["sink_pointer_deref"] == "no"
        and sink["sink_array_index"] == "no"
    )
    read_only_or_observer = (
        low_risk
        and low_effect_io_only
        and role["fn_kind"] in {"io", "utility", "validator"}
        and src["src_user_controlled_likely"] in {"low", "med"}
    )

    null_missing = motif["motif_unlock_without_existence_check"] == "yes" or (
        sink["sink_pointer_deref"] == "yes" and validate["check_null"] == "none"
    )
    bounds_missing = motif["motif_len_to_copy_mismatch"] == "yes" or (
        (sink["sink_memcpy"] == "yes" or sink["sink_array_index"] == "yes") and validate["check_bounds"] == "none"
    )
    ret_missing = motif["motif_return_value_ignored"] == "yes" or (
        validate["check_return_code"] == "none"
        and (sink["sink_write"] == "yes" or sink["sink_unlock"] == "yes" or sink["sink_open"] == "yes")
    )
    auth_state_missing = motif["motif_missing_auth_gate"] == "yes" or (
        contract["contract_requires_auth"] == "yes" and validate["check_auth"] == "none"
    ) or (
        contract["contract_requires_state"] == "yes" and validate["check_state"] == "none"
    )
    lifecycle_missing = motif["motif_incomplete_cleanup"] == "yes" or res["res_cleanup_on_error"] in {"none", "partial"}
    overflow_missing = validate["check_overflow"] == "none" and integ.get("int_size_calc_for_alloc") == "yes"
    sanitize_missing = motif["motif_untrusted_command"] == "yes" or motif["motif_untrusted_path"] == "yes"
    contract_missing = contract["contract_mismatch_likely"] in {"high", "med"}

    if null_missing and risk["risk_memory"] in {"med", "high"}:
        return {"pivot_type": "missing_null_guard", "fix_scope": "local", "safe_flip": "Require a non-null guard before dereference or unlock on this path."}
    if bounds_missing and (risk["risk_memory"] in {"med", "high"} or risk["risk_input"] in {"med", "high"}):
        return {"pivot_type": "missing_bounds_guard", "fix_scope": "local", "safe_flip": "Require a bounds or length check before copy or index use."}
    if ret_missing:
        return {"pivot_type": "unchecked_return_value", "fix_scope": "path", "safe_flip": "Require checking the returned status before proceeding with the risky action."}
    if auth_state_missing:
        return {"pivot_type": "missing_auth_or_state_guard", "fix_scope": "state", "safe_flip": "Require the missing authorization or state guard before the sensitive action."}
    if lifecycle_missing and risk["risk_resource"] in {"med", "high"}:
        return {"pivot_type": "cleanup_or_lifecycle_gap", "fix_scope": "state", "safe_flip": "Repair the lifecycle so that cleanup or release is guaranteed on the failing path."}
    if overflow_missing and risk["risk_integer"] in {"med", "high"}:
        return {"pivot_type": "size_validation_gap", "fix_scope": "local", "safe_flip": "Validate the computed size or range before allocation or copy."}
    if sanitize_missing and risk["risk_input"] in {"med", "high"}:
        return {"pivot_type": "missing_sanitization", "fix_scope": "interface", "safe_flip": "Require trusted or sanitized input before invoking the path or command sink."}
    if contract_missing and risk["risk_contract"] in {"med", "high"}:
        return {"pivot_type": "contract_mismatch", "fix_scope": "interface", "safe_flip": "Align caller-visible assumptions with the checks actually enforced on this path."}

    if validate["check_null"] != "none" and (sink["sink_pointer_deref"] == "yes" or sink["sink_unlock"] == "yes"):
        return {"pivot_type": "present_null_guard", "fix_scope": "local", "safe_flip": "Removing the null guard would reopen the unsafe dereference or unlock path."}
    if validate["check_bounds"] != "none" and (sink["sink_memcpy"] == "yes" or sink["sink_array_index"] == "yes"):
        return {"pivot_type": "present_bounds_guard", "fix_scope": "local", "safe_flip": "Removing the bounds or length check would expose unsafe copy or indexing behavior."}
    if validate["check_return_code"] != "none":
        return {"pivot_type": "present_return_guard", "fix_scope": "path", "safe_flip": "Skipping the status check would allow the risky action to proceed after failure."}
    if validate["check_auth"] != "none" or validate["check_state"] != "none":
        return {"pivot_type": "present_auth_or_state_guard", "fix_scope": "state", "safe_flip": "Removing the auth or state guard would reopen the sensitive path."}
    if res["res_cleanup_on_error"] == "strong":
        return {"pivot_type": "present_lifecycle_guard", "fix_scope": "state", "safe_flip": "Weakening cleanup on the failing path would reintroduce the lifecycle hazard."}
    if any(validate[k] != "none" for k in ["sanitize_string", "sanitize_path", "sanitize_format", "sanitize_command"]):
        return {"pivot_type": "present_sanitization_guard", "fix_scope": "interface", "safe_flip": "Removing the sanitization or canonicalization would make the sink unsafe."}

    if no_dangerous_sink:
        return {"pivot_type": "no_dangerous_sink", "fix_scope": "architectural", "safe_flip": "A dangerous sink would need to be introduced before an additional guard becomes relevant on this path."}
    if no_untrusted_flow and low_risk:
        return {"pivot_type": "no_untrusted_flow_to_sink", "fix_scope": "path", "safe_flip": "A user-controlled value would need to reach a dangerous sink before an explicit guard becomes necessary."}
    if local_only:
        return {"pivot_type": "local_only_computation", "fix_scope": "architectural", "safe_flip": "This path would need to start performing a dangerous effect before a dedicated safety guard is required."}
    if read_only_or_observer:
        return {"pivot_type": "read_only_or_observer_path", "fix_scope": "path", "safe_flip": "A state-changing or dangerous effect would need to be introduced before an additional security guard becomes necessary on this observer path."}
    if low_risk:
        return {"pivot_type": "guard_not_required_for_this_path", "fix_scope": "path", "safe_flip": "A dangerous source-to-sink path would need to appear before an explicit guard becomes necessary here."}
    if risk["risk_overall"] in {"med", "high"}:
        return {"pivot_type": "unsafe_boundary_condition", "fix_scope": "path", "safe_flip": "Adjust the decision-critical branch condition so the unsafe path is blocked."}
    return {"pivot_type": "risk_not_triggered", "fix_scope": "architectural", "safe_flip": "No single local change is required because the risky preconditions are not triggered on this path."}


def _pivot_family(pivot_type: str) -> str:
    if pivot_type in {"missing_null_guard", "present_null_guard"}:
        return "null"
    if pivot_type in {"missing_bounds_guard", "present_bounds_guard"}:
        return "bounds"
    if pivot_type in {"unchecked_return_value", "present_return_guard"}:
        return "return"
    if pivot_type in {"missing_auth_or_state_guard", "present_auth_or_state_guard"}:
        return "auth_state"
    if pivot_type in {"cleanup_or_lifecycle_gap", "present_lifecycle_guard"}:
        return "lifecycle"
    if pivot_type in {"missing_sanitization", "present_sanitization_guard"}:
        return "sanitization"
    if pivot_type == "contract_mismatch":
        return "contract"
    if pivot_type in {"no_dangerous_sink", "no_untrusted_flow_to_sink", "local_only_computation", "read_only_or_observer_path", "guard_not_required_for_this_path", "risk_not_triggered"}:
        return "naturally_safe"
    return "generic"


def _compatible_motifs(profile: Dict[str, Any], pivot_type: str) -> List[str]:
    motif = profile["motif"]
    family = _pivot_family(pivot_type)
    order: List[str]
    if family == "null":
        order = ["motif_unlock_without_existence_check", "motif_use_without_null_guard"]
    elif family == "bounds":
        order = ["motif_len_to_copy_mismatch", "motif_input_to_copy", "motif_input_to_index"]
    elif family == "return":
        order = ["motif_return_value_ignored"]
    elif family == "auth_state":
        order = ["motif_missing_auth_gate", "motif_missing_state_guard"]
    elif family == "lifecycle":
        order = ["motif_incomplete_cleanup"]
    elif family == "sanitization":
        order = ["motif_untrusted_command", "motif_untrusted_path", "motif_untrusted_format"]
    elif family == "contract":
        order = ["motif_global_state_dependency"]
    elif family == "naturally_safe":
        order = []
    else:
        order = [
            "motif_unlock_without_existence_check", "motif_use_without_null_guard", "motif_len_to_copy_mismatch",
            "motif_return_value_ignored", "motif_incomplete_cleanup", "motif_missing_auth_gate",
            "motif_missing_state_guard", "motif_untrusted_command", "motif_untrusted_path",
            "motif_input_to_copy", "motif_input_to_index", "motif_input_to_alloc", "motif_global_state_dependency",
        ]
    return [m for m in order if motif.get(m) == "yes"]



def _compatible_evidence(profile: Dict[str, Any], pivot_type: str) -> List[str]:
    sink = profile["sink"]
    validate = profile["validate"]
    evidence = profile["evidence"]
    contract = profile["contract"]
    src = profile["src"]
    risk = profile["risk"]
    role = profile["role"]
    family = _pivot_family(pivot_type)
    out: List[str] = []
    if family == "null":
        if sink["sink_pointer_deref"] == "yes": out.append("sink_pointer_deref")
        if sink["sink_unlock"] == "yes": out.append("sink_unlock")
        if validate["check_null"] != "none": out.append("check_null_present")
        if contract["contract_requires_nonnull"] == "yes": out.append("contract_requires_nonnull")
    elif family == "bounds":
        if sink["sink_memcpy"] == "yes": out.append("sink_memcpy")
        if sink["sink_array_index"] == "yes": out.append("sink_array_index")
        if validate["check_bounds"] != "none": out.append("check_bounds_present")
        if contract["contract_requires_len"] == "yes": out.append("contract_requires_len")
    elif family == "return":
        if profile["err"]["err_ignored_callee_return"] == "yes": out.append("err_ignored_callee_return")
        if validate["check_return_code"] != "none": out.append("check_return_code_present")
    elif family == "auth_state":
        if validate["check_auth"] != "none": out.append("check_auth_present")
        if validate["check_state"] != "none": out.append("check_state_present")
        if contract["contract_requires_auth"] == "yes": out.append("contract_requires_auth")
        if contract["contract_requires_state"] == "yes": out.append("contract_requires_state")
    elif family == "lifecycle":
        out.append(f"res_cleanup_on_error:{profile['res']['res_cleanup_on_error']}")
        if profile["res"]["res_lock_release"] == "yes": out.append("res_lock_release")
        if profile["res"]["res_alloc_cleanup_pattern"] == "yes": out.append("res_alloc_cleanup_pattern")
    elif family == "sanitization":
        for k in ["sanitize_string", "sanitize_path", "sanitize_format", "sanitize_command"]:
            if validate[k] != "none": out.append(k)
        if src["src_network"] == "yes": out.append("src_network")
        if src["src_file"] == "yes": out.append("src_file")
    elif family == "contract":
        out.append(f"contract_mismatch:{contract['contract_mismatch_likely']}")
        for k in ["contract_requires_nonnull", "contract_requires_len", "contract_requires_state"]:
            if contract[k] == "yes": out.append(k)
    elif family == "naturally_safe":
        if pivot_type == "no_dangerous_sink":
            if sink["sink_count_bucket"] == "0" or sink["sink_family"] == ["none"]: out.append("no_dangerous_sink")
            if evidence["api_tokens"] == ["none"]: out.append("api:none")
            if risk["risk_overall"] == "low": out.append("risk_overall:low")
            if evidence["path_site"] == "main": out.append("path:main")
            return out[:4]
        if pivot_type == "no_untrusted_flow_to_sink":
            if src["src_user_controlled_likely"] == "low" and risk["risk_input"] == "low": out.append("no_untrusted_flow_to_sink")
            if risk["risk_input"] == "low": out.append("risk_input:low")
            if src["src_user_controlled_likely"] == "low": out.append("src_user_controlled_likely:low")
            if evidence["api_tokens"] != ["none"]:
                out.extend([f"api:{api}" for api in evidence["api_tokens"] if api not in {"none", "many"}][:1])
            if risk["risk_overall"] == "low": out.append("risk_overall:low")
            return out[:4]
        if pivot_type == "local_only_computation":
            if role["fn_kind"] in {"utility", "validator"}: out.append(f"fn_kind:{role['fn_kind']}")
            out.append("local_only_computation")
            if risk["risk_overall"] == "low": out.append("risk_overall:low")
            if evidence["api_tokens"] == ["none"]: out.append("api:none")
            return out[:4]
        if pivot_type == "read_only_or_observer_path":
            out.append("observer_or_read_only")
            if sink["sink_read"] == "yes": out.append("sink_read=yes")
            if role["fn_kind"] in {"io", "utility", "validator"}: out.append(f"fn_kind:{role['fn_kind']}")
            if risk["risk_overall"] == "low": out.append("risk_overall:low")
            return out[:4]
        if pivot_type == "guard_not_required_for_this_path":
            if risk["risk_overall"] == "low": out.append("risk_overall:low")
            if evidence["path_site"] == "main": out.append("path:main")
            if src["src_user_controlled_likely"] == "low": out.append("src_user_controlled_likely:low")
            if active := [f"api:{api}" for api in evidence["api_tokens"] if api not in {"none", "many"}]:
                out.extend(active[:1])
            return out[:4]
        if sink["sink_count_bucket"] == "0" or sink["sink_family"] == ["none"]: out.append("no_dangerous_sink")
        if src["src_user_controlled_likely"] == "low" and risk["risk_input"] == "low": out.append("no_untrusted_flow_to_sink")
        if role["fn_kind"] in {"utility", "validator"} and risk["risk_overall"] == "low": out.append("local_only_computation")
        if risk["risk_overall"] == "low": out.append("risk_overall:low")
        if evidence["api_tokens"] == ["none"]: out.append("api:none")
        if evidence["path_site"] == "main": out.append("path:main")
        return out[:4]

    for api in evidence["api_tokens"]:
        if api not in {"none", "many"}:
            token = f"api:{api}"
            if token not in out:
                out.append(token)
    if evidence["path_site"] in {"cleanup", "error"}:
        out.append(f"path:{evidence['path_site']}")
    seen, compact = set(), []
    for x in out:
        if x not in seen:
            compact.append(x)
            seen.add(x)
    return compact[:4]


def _compatible_contracts(profile: Dict[str, Any], pivot_type: str) -> List[str]:
    contract = profile["contract"]
    family = _pivot_family(pivot_type)
    mapping = {
        "null": ["contract_requires_nonnull"],
        "bounds": ["contract_requires_len", "contract_requires_capacity", "contract_ensures_bounds"],
        "return": [],
        "auth_state": ["contract_requires_auth", "contract_requires_state"],
        "lifecycle": ["contract_ensures_release", "contract_requires_state"],
        "sanitization": ["contract_requires_len"],
        "contract": ["contract_requires_nonnull", "contract_requires_len", "contract_requires_state"],
        "naturally_safe": [],
    }
    names: List[str] = []
    for k in mapping.get(family, []):
        if contract.get(k) == "yes":
            names.append(k.replace("contract_", ""))
    if contract["contract_mismatch_likely"] in {"high", "med"} and family in {"contract", "generic"}:
        names.append("mismatch_likely")
    return names[:3]


def _support_items(profile: Dict[str, Any], pivot_type: str) -> List[str]:
    family = _pivot_family(pivot_type)
    src = profile["src"]
    res = profile["res"]
    support = []
    if src["src_param"] != "none": support.append("src_param")
    if src["src_network"] == "yes": support.append("src_network")
    if src["src_file"] == "yes": support.append("src_file")
    if family == "lifecycle" and res["res_cleanup_on_error"] in {"none", "partial", "strong"}: support.append("res_cleanup_on_error")
    if family == "auth_state" and profile["conc"]["conc_state_transition"] in {"med", "high"}: support.append("state_transition")
    return support[:3]


def _risk_items(profile: Dict[str, Any], pivot_type: str) -> List[str]:
    risk = profile["risk"]
    family = _pivot_family(pivot_type)
    order_map = {
        "null": ["risk_memory", "risk_contract", "risk_input"],
        "bounds": ["risk_memory", "risk_input", "risk_contract"],
        "return": ["risk_resource", "risk_contract", "risk_input"],
        "auth_state": ["risk_contract", "risk_input", "risk_concurrency"],
        "lifecycle": ["risk_resource", "risk_contract", "risk_memory"],
        "sanitization": ["risk_input", "risk_contract", "risk_memory"],
        "contract": ["risk_contract", "risk_input", "risk_memory"],
        "naturally_safe": ["risk_overall", "risk_input", "risk_contract"],
        "generic": ["risk_overall", "risk_memory", "risk_input"],
    }
    items: List[str] = []
    for key in order_map.get(family, ["risk_overall"]):
        val = risk.get(key, "low")
        if val != "low":
            items.append(f"{key.replace('risk_', '')}={val}")
    if family == "naturally_safe" and not items:
        items.append("overall=low")
    return items[:3]



def _neutral_sources(profile: Dict[str, Any]) -> List[str]:
    src = profile["src"]
    items: List[str] = []
    if src["src_param"] != "none":
        items.append(f"parameter:{src['src_param']}")
    for key, label in [
        ("src_file", "file"),
        ("src_network", "network"),
        ("src_socket", "socket"),
        ("src_ipc", "ipc"),
        ("src_stdin", "stdin"),
        ("src_env", "env"),
        ("src_argv", "argv"),
        ("src_global", "global"),
        ("src_callee_return", "callee-return"),
        ("src_deserialize", "deserialize"),
    ]:
        if src.get(key) == "yes":
            items.append(label)
    return items[:5] or ["none"]


def _neutral_checks(profile: Dict[str, Any]) -> List[str]:
    validate = profile["validate"]
    mapping = [
        ("check_null", "null-check"),
        ("check_bounds", "bounds-check"),
        ("check_return_code", "return-check"),
        ("check_auth", "auth-check"),
        ("check_state", "state-check"),
        ("sanitize_string", "string-sanitize"),
        ("sanitize_path", "path-sanitize"),
        ("sanitize_command", "command-sanitize"),
    ]
    out: List[str] = []
    for key, label in mapping:
        val = validate.get(key, "none")
        if val != "none":
            out.append(f"{label}={val}")
    return out[:6] or ["none"]


def _neutral_resources(profile: Dict[str, Any]) -> List[str]:
    res = profile["res"]
    out: List[str] = []
    if res.get("res_cleanup_on_error", "none") != "none":
        out.append(f"cleanup-path={res['res_cleanup_on_error']}")
    if res.get("res_alloc_cleanup_pattern", "no") == "yes":
        out.append("alloc-cleanup-pattern=yes")
    if res.get("res_lock_release", "no") == "yes":
        out.append("lock-release=yes")
    return out[:4] or ["none"]


def _neutral_control_flow(profile: Dict[str, Any]) -> List[str]:
    cf = profile["cf"]
    evidence = profile["evidence"]
    call = profile["call"]
    err = profile["err"]
    out = [
        f"branches={cf.get('cf_branch_count_bucket', '0')}",
        f"nesting={cf.get('cf_max_nesting_bucket', '0')}",
        f"path-site={evidence.get('path_site', 'main')}",
    ]
    if call.get("uses_return_of_callee", "none") != "none":
        out.append(f"uses-callee-return={call['uses_return_of_callee']}")
    if err.get("err_ignored_callee_return", "no") == "yes":
        out.append("ignored-callee-return=yes")
    return out[:5]


def build_neutral_profile_text(profile: Dict[str, Any]) -> str:
    evidence = profile["evidence"]
    sink = profile["sink"]
    role = profile["role"]
    contract = profile["contract"]

    apis = [x for x in evidence.get("api_tokens", []) if x != "none"][:5] or ["none"]
    inputs = [x for x in profile["src"].get("input_objects", []) if x != "none"][:5] or ["none"]
    sources = _neutral_sources(profile)
    sinks = [x for x in sink.get("sink_family", []) if x != "none"][:5] or ["none"]
    checks = _neutral_checks(profile)
    resources = _neutral_resources(profile)
    control = _neutral_control_flow(profile)

    contract_items: List[str] = []
    for key in [
        "contract_requires_nonnull",
        "contract_requires_len",
        "contract_requires_capacity",
        "contract_requires_auth",
        "contract_requires_state",
        "contract_ensures_release",
        "contract_ensures_bounds",
    ]:
        if contract.get(key) == "yes":
            contract_items.append(key.replace("contract_", "").replace("_", "-"))
    contract_items = contract_items[:5] or ["none"]

    lines = [
        "[PROFILE]",
        f"Role: fn-kind={role.get('fn_kind', 'unknown')}, visibility={role.get('visibility', 'local')}, returns-pointer={role.get('returns_pointer', 'no')}, returns-status={role.get('returns_status', 'no')}",
        "APIs: " + ", ".join(apis),
        "Inputs: " + ", ".join(inputs),
        "Sources: " + ", ".join(sources),
        "Sinks: " + ", ".join(sinks),
        "Checks observed: " + ", ".join(checks),
        "Control flow: " + ", ".join(control),
        "Resources: " + ", ".join(resources),
        "Contracts observed: " + ", ".join(contract_items),
    ]
    return "\n".join(lines)





def build_task_instruction() -> str:
    return (
        "Decide whether the function is vulnerable or safe using the function code and the neutral profile as supporting evidence. "
        "Base the decision only on observable evidence and do not assume hidden metadata."
    )


def build_strong_security_summary_text(
    profile: Dict[str, Any],
    pivot_type: Optional[str] = None,
    label: Optional[int] = None,
    dataset_name: Optional[str] = None,
) -> str:
    """
    Build a compact evidence-only profile for encoder classification.

    The optional ``label`` argument is accepted for backward compatibility but is
    intentionally ignored. The returned text is derived only from observable
    code features and the label-free pivot.
    """
    src = profile.get("src", {})
    sink = profile.get("sink", {})
    validate = profile.get("validate", {})
    contract = profile.get("contract", {})
    risk = profile.get("risk", {})
    res = profile.get("res", {})
    err = profile.get("err", {})
    mem = profile.get("mem", {})
    integ = profile.get("int", {})
    string = profile.get("str", {})
    conc = profile.get("conc", {})
    role = profile.get("role", {})

    if pivot_type is None:
        pivot_type = str(derive_pivot(profile).get("pivot_type", "unknown"))
    else:
        pivot_type = str(pivot_type or "unknown")

    pivot_family = _pivot_family(pivot_type)

    def uniq(items: Sequence[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for item in items:
            item = (item or "").strip()
            if not item or item == "none" or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    def level(v: Any) -> str:
        return str(v or "low").strip().lower()

    def summary_level(v: Any) -> str:
        lv = level(v)
        if lv == "high":
            return "med"
        if lv not in {"low", "med"}:
            return "med"
        return lv

    def add_line(lines: List[str], prefix: str, items: Sequence[str]) -> None:
        cleaned = uniq(items)
        if cleaned:
            lines.append(prefix + ", ".join(cleaned))

    has_null_check = validate.get("check_null", "none") != "none"
    has_bounds_check = validate.get("check_bounds", "none") != "none"
    has_ret_check = validate.get("check_return_code", "none") != "none"
    has_auth_check = validate.get("check_auth", "none") != "none"
    has_state_check = validate.get("check_state", "none") != "none" or validate.get("check_initialized", "none") != "none"
    has_overflow_check = validate.get("check_overflow", "none") != "none"
    has_sanitization = any(validate.get(k, "none") != "none" for k in ["sanitize_string", "sanitize_path", "sanitize_format", "sanitize_command"])

    null_trigger = (sink.get("sink_pointer_deref") == "yes" or sink.get("sink_unlock") == "yes") and not has_null_check
    bounds_trigger = any(sink.get(k) == "yes" for k in ["sink_memcpy", "sink_strcpy", "sink_strncpy", "sink_strcat", "sink_array_index"]) and not has_bounds_check
    return_trigger = err.get("err_ignored_callee_return") == "yes" and not has_ret_check
    auth_trigger = contract.get("contract_requires_auth") == "yes" and not has_auth_check
    state_trigger = contract.get("contract_requires_state") == "yes" and not has_state_check
    overflow_trigger = integ.get("int_size_calc_for_alloc") == "yes" and not has_overflow_check and level(integ.get("int_truncation_risk", "low")) in {"med", "high"}
    sanitize_trigger = any(sink.get(k) == "yes" for k in ["sink_exec", "sink_system", "sink_open", "sink_printf_family"]) and not has_sanitization and level(risk.get("risk_input", "low")) in {"med", "high"}

    lines: List[str] = ["[PROFILE]"]
    lines.append(f"Role: fn-kind={role.get('fn_kind', 'unknown')}, visibility={role.get('visibility', 'local')}, pivot={pivot_type}")

    inputs: List[str] = []
    src_param = str(src.get("src_param", "none"))
    if src_param != "none":
        inputs.append(f"parameter:{src_param}")
    if src.get("src_callee_return") == "yes":
        inputs.append("callee-return")
    for key, label_name in [
        ("src_network", "network"),
        ("src_file", "file/path"),
        ("src_env", "environment"),
        ("src_argv", "argv"),
        ("src_global", "global-state"),
        ("src_deserialize", "deserialization"),
    ]:
        if src.get(key) == "yes":
            inputs.append(label_name)
    input_objects = [x for x in src.get("input_objects", []) if x != "none"]
    if input_objects:
        inputs.append("objects=" + "/".join(input_objects[:4]))
    add_line(lines, "Inputs/sources: ", inputs)

    ops: List[str] = []
    for key, label_name in [
        ("sink_memcpy", "memcpy/copy"),
        ("sink_printf_family", "format-output"),
        ("sink_open", "file-open"),
        ("sink_read", "read"),
        ("sink_write", "write"),
        ("sink_exec", "exec"),
        ("sink_system", "system"),
        ("sink_lock", "lock"),
        ("sink_unlock", "unlock"),
        ("sink_pointer_deref", "pointer-deref"),
        ("sink_array_index", "array-index"),
    ]:
        if sink.get(key) == "yes":
            ops.append(label_name)
    add_line(lines, "Sensitive operations: ", ops)

    observed: List[str] = []
    if has_null_check:
        observed.append("null-check")
    if has_bounds_check:
        observed.append("bounds/length-check")
    if has_ret_check:
        observed.append("return-check")
    if has_auth_check:
        observed.append("auth-check")
    if has_state_check:
        observed.append("state-check")
    if has_overflow_check:
        observed.append("integer-range-check")
    if has_sanitization:
        observed.append("sanitization")
    add_line(lines, "Observed guards: ", observed)

    missing: List[str] = []
    if null_trigger and pivot_family in {"null", "generic", "auth_state"}:
        missing.append("null-check")
    if bounds_trigger and pivot_family in {"bounds", "generic"}:
        missing.append("bounds/length-check")
    if return_trigger and pivot_family in {"return", "generic"}:
        missing.append("return-check")
    if auth_trigger and pivot_family in {"auth_state", "generic"}:
        missing.append("auth-check")
    if state_trigger and pivot_family in {"auth_state", "generic", "lifecycle"}:
        missing.append("state-check")
    if overflow_trigger and pivot_family in {"bounds", "generic"}:
        missing.append("integer-range-check")
    if sanitize_trigger and pivot_family in {"sanitization", "generic"}:
        missing.append("sanitization")
    add_line(lines, "Potential gaps: ", missing)

    lifetime: List[str] = []
    cleanup = str(res.get("res_cleanup_on_error", "none"))
    if cleanup != "none":
        lifetime.append(f"cleanup-on-error:{cleanup}")
    if res.get("res_alloc_cleanup_pattern") == "yes":
        lifetime.append("alloc-cleanup-pattern")
    if res.get("res_lock_release") == "yes":
        lifetime.append("lock-release")
    if level(res.get("res_asymmetry_risk", "low")) in {"med", "high"}:
        lifetime.append(f"cleanup-asymmetry:{summary_level(res.get('res_asymmetry_risk', 'low'))}")
    add_line(lines, "Resource/lifetime: ", lifetime)

    contracts: List[str] = []
    for key, label_name in [
        ("contract_requires_nonnull", "requires-nonnull"),
        ("contract_requires_len", "requires-valid-length"),
        ("contract_requires_capacity", "requires-capacity"),
        ("contract_requires_state", "requires-valid-state"),
        ("contract_requires_auth", "requires-auth"),
        ("contract_ensures_release", "ensures-release"),
        ("contract_ensures_bounds", "ensures-bounds"),
    ]:
        if contract.get(key) == "yes":
            contracts.append(label_name)
    if level(contract.get("contract_mismatch_likely", "low")) in {"med", "high"}:
        contracts.append(f"contract-mismatch:{summary_level(contract.get('contract_mismatch_likely', 'low'))}")
    add_line(lines, "Contract clues: ", contracts)

    notes: List[str] = []
    if null_trigger and level(mem.get("mem_null_deref_risk", "low")) in {"med", "high"}:
        notes.append(f"null-deref-risk:{summary_level(mem.get('mem_null_deref_risk', 'low'))}")
    if bounds_trigger and level(mem.get("mem_oob_write_risk", "low")) in {"med", "high"}:
        notes.append(f"oob-write-risk:{summary_level(mem.get('mem_oob_write_risk', 'low'))}")
    if bounds_trigger and level(mem.get("mem_len_mismatch_risk", "low")) in {"med", "high"}:
        notes.append(f"copy-length-risk:{summary_level(mem.get('mem_len_mismatch_risk', 'low'))}")
    if overflow_trigger and level(integ.get("int_truncation_risk", "low")) in {"med", "high"}:
        notes.append(f"integer-truncation-risk:{summary_level(integ.get('int_truncation_risk', 'low'))}")
    if sanitize_trigger and sink.get("sink_printf_family") == "yes" and level(string.get("str_format_string_risk", "low")) in {"med", "high"}:
        notes.append(f"format-risk:{summary_level(string.get('str_format_string_risk', 'low'))}")
    if sanitize_trigger and sink.get("sink_open") == "yes" and level(string.get("str_path_traversal_risk", "low")) in {"med", "high"}:
        notes.append(f"path-traversal-risk:{summary_level(string.get('str_path_traversal_risk', 'low'))}")
    if level(conc.get("conc_race_risk", "low")) == "high":
        notes.append("race-risk:med")
    if level(risk.get("risk_overall", "low")) in {"med", "high"} and not notes and missing:
        notes.append(f"overall-risk:{summary_level(risk.get('risk_overall', 'low'))}")
    add_line(lines, "Security note: ", notes[:5])

    if not notes and not missing:
        if sink.get("sink_count_bucket") == "0" or sink.get("sink_family") == ["none"]:
            lines.append("Path note: no concrete risky source-to-sink trigger is evidenced on the current path")
        elif observed:
            lines.append("Path note: observed guards or path conditions limit activation of the sensitive operation on the current path")
        else:
            lines.append("Path note: sensitive operations are present, but no concrete triggered failure signal is evidenced on the current path")

    return "\n".join(lines)



def build_active_context(profile: Dict[str, Any], label: Optional[int] = None) -> Dict[str, Any]:
    """
    Backward-compatible helper used by older preprocessors.
    The optional ``label`` argument is ignored to keep the returned profile
    fully label-free.
    """
    pivot = derive_pivot(profile)
    pivot_type = str(pivot.get("pivot_type", "unknown"))
    summary_text = build_strong_security_summary_text(profile, pivot_type=pivot_type)
    fix_scope = str(pivot.get("fix_scope", "path"))
    safe_flip = str(pivot.get("safe_flip", ""))
    return {
        "text": summary_text,
        "flip_bit": pivot_type,
        "top_motif": pivot_type,
        "fix_scope": fix_scope,
        "safe_flip": safe_flip,
        "evidence_items": [],
        "contract_items": [],
        "support_items": [],
        "risk_items": [],
    }

def build_model_input_text(packed_code_text: str, active_secctx_text: str, task_text: Optional[str] = None) -> str:
    """
    Build classifier input from code followed by a neutral evidence-style profile.

    The profile summarizes observed APIs, inputs, checks, control-flow cues, and
    resource-handling facts. It intentionally excludes direct symbolic label
    proxies such as flip_bit, pivot_type, top_motif, safe_flip, and explicit
    risk verdict buckets.
    """
    task_text = task_text or build_task_instruction()
    parts = ["defect:", "[CODE]", (packed_code_text or "").strip()]
    if (active_secctx_text or "").strip():
        parts.extend(["", (active_secctx_text or "").strip()])
    if (task_text or "").strip():
        parts.extend(["", "[TASK]", task_text.strip()])
    return "\n".join(parts).strip() + "\n"



def build_rationale_prompt_text(packed_code_text: str, active_secctx_text: str, y: int) -> str:
    """
    Build a rationale prompt from code plus the same neutral evidence-style profile.

    The prompt deliberately excludes symbolic label proxies and explicit gold
    decisions. The model must ground the rationale in the function code and the
    neutral profile only.
    """
    profile_block = ""
    if (active_secctx_text or "").strip():
        profile_block = "\n\n" + (active_secctx_text or "").strip()
    return (
        "[CODE]\n"
        + (packed_code_text or "").strip()
        + profile_block
        + "\n\n[TASK]\n"
        + "Produce a compact grounded JSON rationale with fields: "
        + "pivot_type, pivot_anchor, key_evidence, causal_effect, fix_scope, safe_flip, decision, confidence_bucket.\n"
        + "Base every claim on evidence visible in the function code and the neutral profile only. "
        + "Do not rely on hidden metadata, direct verdict labels, or external context.\n"
    )



def _truncate_to_tokens(tokenizer: Any, text: str, max_tokens: int) -> str:
    if max_tokens <= 0 or not text:
        return ""
    lines = text.splitlines()
    kept: List[str] = []
    for line in lines:
        candidate = "\n".join(kept + [line]).strip()
        if _token_len(tokenizer, candidate) <= max_tokens:
            kept.append(line)
        else:
            break
    if kept:
        return "\n".join(kept).strip()
    ids = tokenizer(text, add_special_tokens=False)["input_ids"][:max_tokens]
    return tokenizer.decode(ids, skip_special_tokens=True).strip()


def pack_model_input(code: str, active_secctx_text: str, tokenizer: Any, max_length: int, context_budget_tokens: int, task_budget_tokens: int, head_lines: int, tail_lines: int, evidence_window: int, important_line_indices: Sequence[int]) -> Dict[str, Any]:
    """
    Pack model input for the neutral-profile Option B experiment.

    The classification input is built from packed code plus a compact neutral
    evidence-style profile and a neutral task instruction. active_secctx_text is
    truncated to the context budget and injected after the code as profile text.
    The profile intentionally avoids symbolic answer-key tags and direct verdict
    buckets.
    """
    task_text = _truncate_to_tokens(
        tokenizer,
        build_task_instruction(),
        task_budget_tokens,
    )
    active_secctx_text = _truncate_to_tokens(tokenizer, active_secctx_text, context_budget_tokens)
    code_lines = (code or "").splitlines()
    head = code_lines[: max(0, head_lines)]
    tail = code_lines[-max(0, tail_lines):] if tail_lines > 0 else []
    evidence = _trim_lines_around(code_lines, important_line_indices, window=evidence_window)
    merged: List[str] = []
    seen = set()
    for block in [head, evidence, tail]:
        for line in block:
            key = (line or "").rstrip()
            if key not in seen:
                merged.append(line)
                seen.add(key)
    if not merged:
        merged = code_lines
    structural_overhead = 24
    task_tokens = _token_len(tokenizer, task_text)
    context_tokens = _token_len(tokenizer, active_secctx_text)
    code_budget_tokens = max(64, max_length - task_tokens - context_tokens - structural_overhead)
    packed_code_text = _truncate_to_tokens(tokenizer, "\n".join(merged).strip(), code_budget_tokens)
    model_input_text = build_model_input_text(packed_code_text, active_secctx_text, task_text)
    model_input_tokens = _token_len(tokenizer, model_input_text)
    while model_input_tokens > max_length and packed_code_text:
        lines2 = packed_code_text.splitlines()
        if len(lines2) <= 1:
            break
        packed_code_text = "\n".join(lines2[:-1]).strip()
        model_input_text = build_model_input_text(packed_code_text, active_secctx_text, task_text)
        model_input_tokens = _token_len(tokenizer, model_input_text)
    return {
        "packed_code_text": packed_code_text,
        "active_secctx_text": active_secctx_text,
        "task_text": task_text,
        "model_input_tokens": model_input_tokens,
        "code_budget_tokens": code_budget_tokens,
        "context_budget_tokens": context_budget_tokens,
        "task_budget_tokens": task_budget_tokens,
    }


def generate_grounded_rationale(profile: Dict[str, Any], active_ctx: Dict[str, Any], y: int) -> Dict[str, Any]:
    pivot_type = active_ctx["flip_bit"]
    evidence_items = list(active_ctx["evidence_items"])[:4]
    vuln_causal = {
        "missing_null_guard": "The path performs a null-sensitive action without a reliable null check, so safety depends on an unchecked pointer condition.",
        "missing_bounds_guard": "The path reaches a copy or index operation without a sufficient bounds or length check, so memory safety depends on unchecked size assumptions.",
        "unchecked_return_value": "The path proceeds after a callee result that should be checked, so safety depends on an unchecked failure signal.",
        "missing_auth_or_state_guard": "The path performs a sensitive action without the needed auth or state condition, so unsafe behavior remains reachable.",
        "cleanup_or_lifecycle_gap": "The path acquires or allocates state without guaranteeing consistent cleanup or release across failure paths.",
        "size_validation_gap": "A computed size influences memory behavior without a validating range or overflow check.",
        "missing_sanitization": "Untrusted input can reach a path or command-sensitive sink without a protecting sanitization step.",
        "contract_mismatch": "The path relies on a precondition that is not enforced locally, so safety depends on an external contract.",
        "unsafe_boundary_condition": "A decision-critical condition leaves the unsafe path reachable under insufficient constraints.",
        "unknown": GENERIC_VULN_CAUSAL,
    }
    safe_causal = {
        "present_null_guard": "The current path remains safe because the null-sensitive action is protected by an explicit non-null condition.",
        "present_bounds_guard": "The current path remains safe because copy or indexing behavior is constrained by an explicit bounds or length condition.",
        "present_return_guard": "The current path remains safe because the code checks the returned status before continuing.",
        "present_auth_or_state_guard": "The current path remains safe because the sensitive action is blocked unless the required auth or state condition holds.",
        "present_lifecycle_guard": "The current path remains safe because cleanup or release is enforced on the relevant path.",
        "present_sanitization_guard": "The current path remains safe because input is sanitized or constrained before reaching the sink.",
        "no_dangerous_sink": "The current path remains safe because it does not expose a dangerous sink that would require a dedicated security guard.",
        "no_untrusted_flow_to_sink": "The current path remains safe because user-controlled data does not reach a dangerous sink on this path.",
        "local_only_computation": "The current path remains safe because it only performs local low-risk computation rather than a dangerous effect.",
        "read_only_or_observer_path": "The current path remains safe because it only observes or reads state and does not perform a dangerous state-changing effect on this path.",
        "guard_not_required_for_this_path": "The current path remains safe because the risky source-to-sink condition does not arise here, so an additional guard is not required on this path.",
        "risk_not_triggered": "The current path remains safe because the risky preconditions are not triggered in this function.",
        "unknown": GENERIC_SAFE_CAUSAL,
    }
    conf = "high" if profile["risk"]["risk_overall"] == ("high" if y == 1 else "low") else "medium"
    if y == 1 and profile["risk"]["risk_overall"] == "low":
        conf = "low"
    if y == 1 and not evidence_items:
        evidence_items = ["risk_family_match_missing"]
    if y == 0 and _pivot_family(pivot_type) == "naturally_safe" and not evidence_items:
        evidence_items = ["risk_overall:low"]
    return {
        "pivot_type": pivot_type,
        "pivot_anchor": _pivot_anchor_from_family(pivot_type),
        "key_evidence": evidence_items,
        "causal_effect": (vuln_causal if y == 1 else safe_causal).get(pivot_type, GENERIC_VULN_CAUSAL if y == 1 else GENERIC_SAFE_CAUSAL),
        "fix_scope": active_ctx["fix_scope"],
        "safe_flip": active_ctx["safe_flip"],
        "decision": "vulnerable" if int(y) == 1 else "safe",
        "confidence_bucket": conf,
    }


def rationale_to_text(rationale: Dict[str, Any]) -> str:
    return json.dumps(rationale, ensure_ascii=False, sort_keys=True)


def _quality_penalty_generic(text: str) -> float:
    text_low = (text or "").strip().lower()
    generic = [
        "the current path remains safe because the relevant risky condition is blocked or does not arise on this path",
        "the current path is unsafe because the decision-critical safeguard is missing on a risky path",
    ]
    return 0.15 if any(g in text_low for g in generic) else 0.0


def _motif_family(top_motif: str) -> str:
    m = (top_motif or "none").strip().lower()
    if m in {"use_without_null_guard", "unlock_without_existence_check"}:
        return "null"
    if m in {"len_to_copy_mismatch", "input_to_copy", "input_to_index", "input_to_alloc"}:
        return "bounds"
    if m in {"return_value_ignored"}:
        return "return"
    if m in {"missing_auth_gate", "missing_state_guard"}:
        return "auth_state"
    if m in {"incomplete_cleanup"}:
        return "lifecycle"
    if m in {"untrusted_command", "untrusted_path", "untrusted_format"}:
        return "sanitization"
    if m in {"global_state_dependency"}:
        return "contract"
    return "none"


def _has_family_evidence(family: str, evidence_items: Sequence[str]) -> bool:
    evs = [str(ev).lower() for ev in evidence_items]
    if family == "null":
        return any(("null" in ev or "pointer" in ev or "unlock" in ev or "nonnull" in ev) for ev in evs)
    if family == "bounds":
        return any(("bound" in ev or "len" in ev or "array" in ev or "memcpy" in ev or "copy" in ev or "index" in ev) for ev in evs)
    if family == "return":
        return any(("return" in ev or "callee" in ev or "check_return" in ev or "status" in ev) for ev in evs)
    if family == "auth_state":
        return any(("auth" in ev or "state" in ev or "permission" in ev) for ev in evs)
    if family == "lifecycle":
        return any(("cleanup" in ev or "release" in ev or "alloc" in ev or "lock" in ev) for ev in evs)
    if family == "sanitization":
        return any(("sanitize" in ev or "src_" in ev or "command" in ev or "path" in ev) for ev in evs)
    if family == "contract":
        return any(("contract" in ev or "mismatch" in ev or "requires_" in ev) for ev in evs)
    if family == "naturally_safe":
        return any(ev in {"no_dangerous_sink", "no_untrusted_flow_to_sink", "local_only_computation", "read_only_or_observer_path", "observer_or_read_only", "risk_overall:low", "risk_input:low", "src_user_controlled_likely:low", "api:none", "path:main"} for ev in evs)
    return False


def _generic_anchor_penalty(pivot_anchor: str, family: str) -> float:
    anchor = (pivot_anchor or "").strip().lower()
    generic_exact = {
        "decision-critical branch on the main path",
        "path-level absence of a dangerous effect or risky flow",
    }
    if anchor in generic_exact:
        return 0.05
    if family == "generic" or len(anchor) < 12:
        return 0.05
    return 0.0


def _generic_safe_flip_penalty(safe_flip: str, pivot_type: str) -> float:
    sf = (safe_flip or "").strip().lower()
    generic_phrases = [
        "adjust the decision-critical branch condition",
        "strengthen the missing safety condition",
        "dangerous source-to-sink path would need to appear",
        "dangerous sink would need to be introduced",
        "no single local change is required",
    ]
    if any(p in sf for p in generic_phrases):
        return 0.05
    if pivot_type == "unknown":
        return 0.05
    return 0.0



def validate_grounded_rationale(rationale: Dict[str, Any], profile: Dict[str, Any], active_ctx: Dict[str, Any], y: int, model_input_tokens: Optional[int] = None) -> Dict[str, Any]:
    reasons: List[str] = []
    valid = True
    quality = 1.0

    required = ["pivot_type", "pivot_anchor", "key_evidence", "causal_effect", "fix_scope", "safe_flip", "decision", "confidence_bucket"]
    decision = str(rationale.get("decision", "")).strip().lower()
    expected = "vulnerable" if int(y) == 1 else "safe"
    pivot_type = str(rationale.get("pivot_type", "")).strip()
    pivot_anchor = str(rationale.get("pivot_anchor", "")).strip()
    causal_text = str(rationale.get("causal_effect", "")).strip()
    safe_flip = str(rationale.get("safe_flip", "")).strip()
    fix_scope = str(rationale.get("fix_scope", "")).strip()
    conf_bucket = str(rationale.get("confidence_bucket", "")).strip()
    evidence_items = rationale.get("key_evidence", [])

    for k in required:
        if k not in rationale:
            valid = False
            quality -= 0.30
            reasons.append(f"missing:{k}")

    if decision != expected:
        valid = False
        quality -= 0.70
        reasons.append("decision_mismatch")

    if pivot_type not in PIVOT_TYPES:
        valid = False
        quality -= 0.40
        reasons.append("invalid_pivot_type")

    if fix_scope not in FIX_SCOPE_VALUES:
        valid = False
        quality -= 0.20
        reasons.append("invalid_fix_scope")

    if conf_bucket not in {"low", "medium", "high"}:
        valid = False
        quality -= 0.15
        reasons.append("invalid_confidence_bucket")

    if not isinstance(evidence_items, list):
        evidence_items = []
        valid = False
        quality -= 0.25
        reasons.append("evidence_not_list")

    family = _pivot_family(pivot_type)
    motif = active_ctx.get("top_motif", "none")
    motif_family = _motif_family(motif)
    active_evidence = set(active_ctx.get("evidence_items", []))
    allowed_evidence = set(_compatible_evidence(profile, pivot_type))
    grounded_items = [ev for ev in evidence_items if ev in allowed_evidence or ev in active_evidence]
    grounded_count = len(grounded_items)
    has_family_evidence = _has_family_evidence(family, evidence_items)

    # Weak evidence penalties for vulnerable samples
    if int(y) == 1:
        if grounded_count < 2:
            quality -= 0.10
            reasons.append("weak_grounded_evidence_count")
        if evidence_items and all(str(ev).startswith("api:") for ev in evidence_items) and not has_family_evidence:
            quality -= 0.05
            reasons.append("generic_api_only_evidence")

    # Weak rationale structure penalties
    anchor_pen = _generic_anchor_penalty(pivot_anchor, family)
    if anchor_pen > 0:
        quality -= anchor_pen
        reasons.append("generic_pivot_anchor")

    if _quality_penalty_generic(causal_text) > 0:
        quality -= 0.05
        reasons.append("generic_causal_effect")

    safe_flip_pen = _generic_safe_flip_penalty(safe_flip, pivot_type)
    if safe_flip_pen > 0:
        quality -= safe_flip_pen
        reasons.append("generic_safe_flip")

    # Weak alignment penalties for vulnerable samples
    if int(y) == 1:
        if motif == "none" and family not in {"lifecycle", "return", "contract"}:
            quality -= 0.15
            reasons.append("positive_motif_none")
        elif motif_family not in {family, "none"}:
            quality -= 0.10
            reasons.append("pivot_motif_family_mismatch")

        if family in {"null", "bounds", "return"} and not has_family_evidence:
            quality -= 0.10
            reasons.append("positive_family_evidence_missing")

    # Multi-level safe-sample penalties
    if int(y) == 0:
        unsafe_looking_motif = motif not in {"none", ""}
        strong_absence = {
            "no_dangerous_sink",
            "no_untrusted_flow_to_sink",
            "local_only_computation",
            "observer_or_read_only",
            "read_only_or_observer_path",
            "risk_overall:low",
            "risk_input:low",
            "src_user_controlled_likely:low",
            "api:none",
        }
        weak_absence = {
            "path:main",
            "fn_kind:utility",
            "fn_kind:validator",
            "fn_kind:io",
        }
        evidence_set = {str(ev) for ev in evidence_items}
        strong_absence_count = len([ev for ev in evidence_set if ev in strong_absence])
        weak_absence_count = len([ev for ev in evidence_set if ev in weak_absence])

        if family == "naturally_safe":
            if strong_absence_count == 0 and weak_absence_count == 0:
                quality -= 0.10
                reasons.append("naturally_safe_no_absence_evidence")
            elif strong_absence_count == 0 and weak_absence_count == 1:
                quality -= 0.05
                reasons.append("naturally_safe_only_weak_absence_evidence")
            elif strong_absence_count == 1:
                quality -= 0.05
                reasons.append("naturally_safe_single_strong_absence_evidence")

            if pivot_type == "risk_not_triggered" and profile["risk"]["risk_overall"] != "low":
                quality -= 0.05
                reasons.append("risk_not_triggered_but_risk_not_low")

            if unsafe_looking_motif:
                quality -= 0.10
                reasons.append("naturally_safe_with_unsafe_motif")

            if _quality_penalty_generic(causal_text) > 0:
                quality -= 0.05
                reasons.append("naturally_safe_generic_causal_effect")

            if safe_flip_pen > 0:
                quality -= 0.05
                reasons.append("naturally_safe_vague_safe_flip")

        if pivot_type.startswith("present_"):
            guard_evidence = {
                "present_null_guard": any(("null" in str(ev).lower() or "nonnull" in str(ev).lower()) for ev in evidence_items),
                "present_bounds_guard": any(("bound" in str(ev).lower() or "len" in str(ev).lower()) for ev in evidence_items),
                "present_return_guard": any(("return" in str(ev).lower() or "status" in str(ev).lower()) for ev in evidence_items),
                "present_auth_or_state_guard": any(("auth" in str(ev).lower() or "state" in str(ev).lower()) for ev in evidence_items),
                "present_lifecycle_guard": any(("cleanup" in str(ev).lower() or "release" in str(ev).lower()) for ev in evidence_items),
                "present_sanitization_guard": any(("sanitize" in str(ev).lower() or "path" in str(ev).lower() or "command" in str(ev).lower()) for ev in evidence_items),
            }.get(pivot_type, True)

            if not guard_evidence:
                quality -= 0.10
                reasons.append("safe_guard_evidence_weak")

            if pivot_type == "present_bounds_guard" and not any(profile["sink"][k] == "yes" for k in ["sink_memcpy", "sink_array_index"]):
                quality -= 0.05
                reasons.append("safe_bounds_guard_without_matching_sink")

            if pivot_type == "present_null_guard" and not any(profile["sink"][k] == "yes" for k in ["sink_pointer_deref", "sink_unlock"]):
                quality -= 0.05
                reasons.append("safe_null_guard_without_matching_sink")

            if unsafe_looking_motif:
                quality -= 0.10
                reasons.append("unsafe_looking_motif_for_safe_case")

            if _quality_penalty_generic(causal_text) > 0:
                quality -= 0.05
                reasons.append("safe_generic_causal_effect")

            if safe_flip_pen > 0:
                quality -= 0.05
                reasons.append("safe_vague_safe_flip")

    # Generic penalties that apply to both sides
    if not evidence_items:
        quality -= 0.18
        reasons.append("empty_evidence")
    if grounded_count == 0 and family != "naturally_safe":
        quality -= 0.15
        reasons.append("evidence_not_grounded")
    if len(pivot_anchor) < 8:
        quality -= 0.05
        reasons.append("weak_pivot_anchor")
    if not safe_flip:
        valid = False
        quality -= 0.20
        reasons.append("empty_safe_flip")

    # Hard / truncated case penalties
    toks = int(model_input_tokens) if model_input_tokens is not None else None
    if toks is not None and toks > 3000:
        quality -= 0.05
        reasons.append("long_input_over_3000")
    if toks is not None and toks > 3600:
        quality -= 0.05
        reasons.append("long_input_over_3600")

    quality = max(0.0, min(1.0, round(quality, 3)))
    keep_flag = 1 if valid and quality >= 0.65 else 0
    return {"valid": int(valid), "quality": quality, "keep_flag": keep_flag, "reasons": sorted(set(reasons))}


    required = ["pivot_type", "pivot_anchor", "key_evidence", "causal_effect", "fix_scope", "safe_flip", "decision", "confidence_bucket"]
    decision = str(rationale.get("decision", "")).strip().lower()
    expected = "vulnerable" if int(y) == 1 else "safe"
    pivot_type = str(rationale.get("pivot_type", "")).strip()
    pivot_anchor = str(rationale.get("pivot_anchor", "")).strip()
    causal_text = str(rationale.get("causal_effect", "")).strip()
    safe_flip = str(rationale.get("safe_flip", "")).strip()
    fix_scope = str(rationale.get("fix_scope", "")).strip()
    conf_bucket = str(rationale.get("confidence_bucket", "")).strip()
    evidence_items = rationale.get("key_evidence", [])

    for k in required:
        if k not in rationale:
            valid = False
            quality -= 0.30
            reasons.append(f"missing:{k}")

    if decision != expected:
        valid = False
        quality -= 0.70
        reasons.append("decision_mismatch")

    if pivot_type not in PIVOT_TYPES:
        valid = False
        quality -= 0.40
        reasons.append("invalid_pivot_type")

    if fix_scope not in FIX_SCOPE_VALUES:
        valid = False
        quality -= 0.20
        reasons.append("invalid_fix_scope")

    if conf_bucket not in {"low", "medium", "high"}:
        valid = False
        quality -= 0.15
        reasons.append("invalid_confidence_bucket")

    if not isinstance(evidence_items, list):
        evidence_items = []
        valid = False
        quality -= 0.25
        reasons.append("evidence_not_list")

    family = _pivot_family(pivot_type)
    motif = active_ctx.get("top_motif", "none")
    motif_family = _motif_family(motif)
    active_evidence = set(active_ctx.get("evidence_items", []))
    allowed_evidence = set(_compatible_evidence(profile, pivot_type))
    grounded_items = [ev for ev in evidence_items if ev in allowed_evidence or ev in active_evidence]
    grounded_count = len(grounded_items)
    has_family_evidence = _has_family_evidence(family, evidence_items)

    # Weak evidence penalties for vulnerable samples
    if int(y) == 1:
        if grounded_count < 2:
            quality -= 0.10
            reasons.append("weak_grounded_evidence_count")
        if evidence_items and all(str(ev).startswith("api:") for ev in evidence_items) and not has_family_evidence:
            quality -= 0.05
            reasons.append("generic_api_only_evidence")

    # Weak rationale structure penalties
    anchor_pen = _generic_anchor_penalty(pivot_anchor, family)
    if anchor_pen > 0:
        quality -= anchor_pen
        reasons.append("generic_pivot_anchor")

    if _quality_penalty_generic(causal_text) > 0:
        quality -= 0.05
        reasons.append("generic_causal_effect")

    safe_flip_pen = _generic_safe_flip_penalty(safe_flip, pivot_type)
    if safe_flip_pen > 0:
        quality -= safe_flip_pen
        reasons.append("generic_safe_flip")

    # Weak alignment penalties for vulnerable samples
    if int(y) == 1:
        if motif == "none" and family not in {"lifecycle", "return", "contract"}:
            quality -= 0.15
            reasons.append("positive_motif_none")
        elif motif_family not in {family, "none"}:
            quality -= 0.10
            reasons.append("pivot_motif_family_mismatch")

        if family in {"null", "bounds", "return"} and not has_family_evidence:
            quality -= 0.10
            reasons.append("positive_family_evidence_missing")

    # Safe-sample penalties
    if int(y) == 0:
        unsafe_looking_motif = motif not in {"none", ""}
        if family == "naturally_safe":
            if profile["risk"]["risk_overall"] != "low":
                quality -= 0.10
                reasons.append("naturally_safe_but_risk_not_low")
            absence_markers = {"no_dangerous_sink", "no_untrusted_flow_to_sink", "risk_overall:low", "api:none", "local_only_computation", "path:main"}
            if not any(ev in absence_markers for ev in evidence_items):
                quality -= 0.10
                reasons.append("naturally_safe_absence_evidence_missing")
        if pivot_type.startswith("present_"):
            guard_evidence = {
                "present_null_guard": any(("null" in str(ev).lower() or "nonnull" in str(ev).lower()) for ev in evidence_items),
                "present_bounds_guard": any(("bound" in str(ev).lower() or "len" in str(ev).lower()) for ev in evidence_items),
                "present_return_guard": any(("return" in str(ev).lower() or "status" in str(ev).lower()) for ev in evidence_items),
                "present_auth_or_state_guard": any(("auth" in str(ev).lower() or "state" in str(ev).lower()) for ev in evidence_items),
                "present_lifecycle_guard": any(("cleanup" in str(ev).lower() or "release" in str(ev).lower()) for ev in evidence_items),
                "present_sanitization_guard": any(("sanitize" in str(ev).lower() or "path" in str(ev).lower() or "command" in str(ev).lower()) for ev in evidence_items),
            }.get(pivot_type, True)
            if not guard_evidence:
                quality -= 0.10
                reasons.append("safe_guard_evidence_weak")
            if pivot_type == "present_bounds_guard" and not any(profile["sink"][k] == "yes" for k in ["sink_memcpy", "sink_array_index"]):
                quality -= 0.05
                reasons.append("safe_bounds_guard_without_matching_sink")
            if pivot_type == "present_null_guard" and not any(profile["sink"][k] == "yes" for k in ["sink_pointer_deref", "sink_unlock"]):
                quality -= 0.05
                reasons.append("safe_null_guard_without_matching_sink")
        if unsafe_looking_motif:
            quality -= 0.10
            reasons.append("unsafe_looking_motif_for_safe_case")
        if _quality_penalty_generic(causal_text) > 0:
            quality -= 0.05
            reasons.append("safe_generic_causal_effect")
        if safe_flip_pen > 0:
            quality -= 0.05
            reasons.append("safe_vague_safe_flip")

    # Generic penalties that apply to both sides
    if not evidence_items:
        quality -= 0.18
        reasons.append("empty_evidence")
    if grounded_count == 0 and family != "naturally_safe":
        quality -= 0.15
        reasons.append("evidence_not_grounded")
    if len(pivot_anchor) < 8:
        quality -= 0.05
        reasons.append("weak_pivot_anchor")
    if not safe_flip:
        valid = False
        quality -= 0.20
        reasons.append("empty_safe_flip")

    # Hard / truncated case penalties
    toks = int(model_input_tokens) if model_input_tokens is not None else None
    if toks is not None and toks > 3000:
        quality -= 0.05
        reasons.append("long_input_over_3000")
    if toks is not None and toks > 3600:
        quality -= 0.05
        reasons.append("long_input_over_3600")

    quality = max(0.0, min(1.0, round(quality, 3)))
    keep_flag = 1 if valid and quality >= 0.65 else 0
    return {"valid": int(valid), "quality": quality, "keep_flag": keep_flag, "reasons": sorted(set(reasons))}



def _pivot_anchor_from_family(pivot_type: str) -> str:
    family = _pivot_family(pivot_type)
    mapping = {
        "null": "pointer dereference or unlock on the main path",
        "bounds": "copy or index use on the main path",
        "return": "status-dependent action on the main path",
        "auth_state": "state or authorization gate on the sensitive path",
        "lifecycle": "cleanup or release behavior on the failing path",
        "sanitization": "untrusted input reaching a sensitive sink",
        "contract": "caller-visible contract on the risky path",
        "generic": "decision-critical branch on the current path",
    }
    return mapping.get(family, "decision-critical path condition")
# ======================================================================
# LineVul dataset adapter overrides
# Added for the LineVul public Big-Vul-derived split.
# This keeps the same RCC/static profiling logic as the PrimeVul utility,
# but allows dataset_name='linevul' to resolve cleanly.
# ======================================================================

_rcc_orig_normalize_dataset_name = normalize_dataset_name
_rcc_orig_dataset_token = dataset_token
_rcc_orig_dataset_id = dataset_id


def normalize_dataset_name(name):
    s = str(name or "").strip().lower()
    if s in {
        "linevul",
        "linevul_paper_bigvul",
        "linevul-public-bigvul",
        "linevul_public_bigvul",
        "lv",
    }:
        return "linevul"
    return _rcc_orig_normalize_dataset_name(name)


def dataset_token(name):
    ds = normalize_dataset_name(name)
    if ds == "linevul":
        return "LV"
    return _rcc_orig_dataset_token(name)


def dataset_id(name):
    ds = normalize_dataset_name(name)
    if ds == "linevul":
        return 3
    return _rcc_orig_dataset_id(name)
