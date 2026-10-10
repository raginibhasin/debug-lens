"""Error / stack-trace parsing and root-cause investigation.

Output deliberately separates `verified` (facts extracted from the input) from
`possible_causes` (hypotheses from a rule base) - an error message alone rarely
proves the root cause.
"""
import re

PY_FRAME = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>.+))?')
PY_EXC = re.compile(r'^(?P<type>[A-Za-z_][\w.]*(?:Error|Exception|Warning|Exit|Interrupt))(?::\s*(?P<msg>.*))?\s*$')
CS_COMPILE = re.compile(r'(?P<file>[^\s(][^()]*?)\((?P<line>\d+),(?P<col>\d+)\):\s*(?P<sev>error|warning)\s+(?P<code>CS\d+):\s*(?P<msg>.*)')
CS_EXC = re.compile(r'(?P<type>System\.(?:\w+\.)*\w*Exception):\s*(?P<msg>.*)')
CS_FRAME = re.compile(r'\bat\s+(?P<func>\S.*?)\s+in\s+(?P<file>.+?):line\s+(?P<line>\d+)')
JAVA_EXC = re.compile(r'(?:Exception in thread "[^"]+"\s+|Caused by:\s+)?(?P<type>(?:[a-z_]\w*\.)+[A-Z][\w$]*(?:Exception|Error))(?::\s*(?P<msg>.*))?')
JAVA_FRAME = re.compile(r'\bat\s+(?P<func>[\w$.<>]+)\((?P<file>[\w$]+\.(?:java|kt|scala)):(?P<line>\d+)\)')
JS_EXC = re.compile(r'^(?:Uncaught\s+)?(?P<type>(?:Type|Reference|Syntax|Range|Eval|URI)?Error):\s*(?P<msg>.*)')
JS_FRAME = re.compile(r'\bat\s+(?:(?P<func>[^\s(]+)\s+\()?(?P<file>[^\s()]+?):(?P<line>\d+):(?P<col>\d+)\)?')


def E(category, explain, causes, fixes, concept):
    return {"category": category, "explain": explain, "causes": causes, "fixes": fixes, "concept": concept}


KB = {
    "ZeroDivisionError": E("Arithmetic", "The program divided a number by zero.",
        ["A divisor variable is 0 (e.g. an empty list's length)", "Input data was not validated before dividing"],
        ["Check the divisor before dividing", "Handle the empty/zero case explicitly"],
        "Division by zero is undefined; guard against it with a condition or exception handler."),
    "TypeError": E("Type", "An operation was applied to a value of the wrong type (or a value was called/indexed that cannot be).",
        ["Mixing types such as str + int", "A variable is None/undefined when an object was expected", "A function was called with the wrong arguments"],
        ["Print/inspect the types involved (type() / typeof)", "Convert explicitly, e.g. int(x) or str(x)", "Check where the value is assigned"],
        "Dynamic languages check types at run time, so wrong-type operations only fail when executed."),
    "ValueError": E("Value", "A value has the right type but an unacceptable content.",
        ["Parsing non-numeric text with int()/float()", "Unpacking the wrong number of items"],
        ["Validate input before converting", "Wrap conversion in try/except and report a friendly message"],
        "Type is correct, value is not: validate and sanitise input at boundaries."),
    "KeyError": E("Lookup", "A dictionary key that does not exist was accessed.",
        ["Typo in the key", "Data missing from an API/JSON response", "Key was never inserted on this code path"],
        ["Use dict.get(key, default)", "Check `if key in d` first", "Print d.keys() to compare"],
        "Dictionaries raise KeyError for missing keys; .get() returns a default instead."),
    "IndexError": E("Lookup", "A list/tuple index was outside the valid range.",
        ["Off-by-one in a loop", "The list is empty", "Index computed from stale data"],
        ["Check len(seq) first", "Use range(len(seq)) or iterate directly", "Remember valid indexes are 0..len-1"],
        "Zero-based indexing: valid indexes run from 0 to length-1."),
    "AttributeError": E("Type", "An attribute or method does not exist on that object.",
        ["Object is None", "Typo in attribute name", "Wrong type of object (e.g. list instead of str)"],
        ["Print type(obj) and dir(obj)", "Trace where the object is created; check for None returns"],
        "Attributes belong to the object's class; None has almost none."),
    "NameError": E("Name", "A name was used before it was defined.",
        ["Typo in variable/function name", "Variable defined in another scope", "Missing import"],
        ["Check spelling and scope", "Define the variable before use", "Add the missing import"],
        "Scope decides which names are visible at each point of the program."),
    "ModuleNotFoundError": E("Import", "Python could not find the module being imported.",
        ["Package not installed in the active environment", "Wrong virtual environment selected", "Wrong module name or relative import"],
        ["pip install <package> in the active venv", "Check the interpreter selected in VS Code", "Verify file/folder names"],
        "Imports are resolved via sys.path and the active environment."),
    "ImportError": E("Import", "An import statement failed.",
        ["Circular import", "Name does not exist in that module", "Version mismatch"],
        ["Check the module for that name", "Break circular imports (move imports inside functions)"],
        "Python executes modules on import; circular imports see half-initialised modules."),
    "FileNotFoundError": E("I/O", "The file or directory does not exist at that path.",
        ["Wrong working directory", "Relative path used", "Typo or wrong extension"],
        ["Print os.getcwd() and the path", "Use pathlib with an absolute path based on __file__"],
        "Relative paths depend on the process working directory, not the script location."),
    "PermissionError": E("I/O", "The OS denied access to the file/resource.",
        ["File is open in another program", "Trying to open a directory as a file", "Insufficient rights"],
        ["Close other programs using the file", "Check the path and permissions"], "File access is governed by OS permissions."),
    "SyntaxError": E("Syntax", "The code does not follow the language grammar, so it never started running.",
        ["Missing colon/bracket/quote", "Unclosed parenthesis on a previous line", "Python 2 syntax in Python 3"],
        ["Look at the reported line AND the line before it", "Use an editor with bracket matching"], "Code is parsed completely before execution."),
    "IndentationError": E("Syntax", "Python block indentation is inconsistent.",
        ["Mixed tabs and spaces", "Missing indented body after a colon"], ["Use 4 spaces consistently", "Enable 'render whitespace' in VS Code"],
        "Python uses indentation to define blocks."),
    "RecursionError": E("Runtime", "Recursion exceeded the maximum depth.",
        ["Missing/incorrect base case", "Recursion on data that never shrinks"], ["Verify the base case", "Convert to an iterative loop"],
        "Every call uses stack space; recursion must converge on a base case."),
    "NullReferenceException": E("Null", "A member was accessed on a null object (C#).",
        ["Variable never assigned", "Method returned null", "Dependency not injected / collection not initialised"],
        ["Check for null (`?.`, `??`, `is null`)", "Enable nullable reference types", "Initialise objects before use"],
        "Reference types can be null; accessing members of null throws."),
    "InvalidCastException": E("Type", "An object was cast to an incompatible type.",
        ["Wrong runtime type stored in object/collection", "Unboxing mismatch"], ["Use `as`/`is` pattern matching", "Use Convert/Parse methods for conversions"],
        "Explicit casts are checked at run time."),
    "IndexOutOfRangeException": E("Lookup", "Array index outside bounds (C#).",
        ["Off-by-one", "Empty array"], ["Check Length", "Use foreach"], "Arrays are zero-based and fixed size."),
    "FormatException": E("Value", "A string was not in the expected format for conversion.",
        ["Parsing user input with int.Parse", "Culture-specific number formats"], ["Use TryParse", "Specify CultureInfo.InvariantCulture"],
        "Parse methods throw; TryParse returns false instead."),
    "NullPointerException": E("Null", "A method/field was used on a null reference (Java).",
        ["Object never initialised", "Method returned null", "Missing @Autowired/dependency"],
        ["Add null checks or use Optional", "Initialise fields", "Read the exact line in the trace"],
        "A null reference points to no object."),
    "ArrayIndexOutOfBoundsException": E("Lookup", "Array index outside bounds (Java).",
        ["Loop uses <= length", "Empty array"], ["Loop with i < arr.length"], "Valid indexes are 0..length-1."),
    "ClassCastException": E("Type", "Object cast to an incompatible class (Java).",
        ["Raw/generic collection mismatch"], ["Use instanceof before casting", "Use generics"], "Casts are validated at run time."),
    "NumberFormatException": E("Value", "A string could not be parsed as a number (Java).",
        ["Empty or non-numeric string", "Whitespace in input"], ["trim() and validate", "Catch the exception"], "Parsing is strict."),
    "StackOverflowError": E("Runtime", "The call stack overflowed (Java).",
        ["Infinite recursion"], ["Fix the base case", "Use iteration"], "Stack space is limited per thread."),
    "ReferenceError": E("Name", "A variable was used that is not defined (JavaScript).",
        ["Typo", "Variable declared in another scope", "Use before let/const initialisation", "Missing import"],
        ["Check spelling and scope", "Declare before use"], "let/const are block scoped and not usable before declaration."),
    "RangeError": E("Value", "A value is outside the allowed range (JavaScript).",
        ["Infinite recursion", "Invalid array length"], ["Fix recursion base case", "Validate numeric input"], "Some built-ins validate numeric ranges."),
    "CS0029": E("Type", "Cannot implicitly convert between the two types (C# compiler).",
        ["Assigning string to int (or similar)", "Missing cast or Parse call"],
        ["Use int.Parse/TryParse or Convert.ToInt32", "Change the variable's declared type"],
        "C# is statically typed; conversions between unrelated types must be explicit."),
    "CS0103": E("Name", "The name does not exist in the current context (C#).",
        ["Typo", "Variable out of scope", "Missing `using` directive"], ["Check spelling/scope", "Add the using directive"], "Names must be declared in an enclosing scope."),
    "CS0246": E("Import", "Type or namespace could not be found (C#).",
        ["Missing using directive", "Missing NuGet package/assembly reference"], ["Add `using`", "dotnet add package <name>"], "Types come from referenced assemblies and namespaces."),
    "CS1002": E("Syntax", "A semicolon is expected (C#).", ["Missing `;` on this or the previous line"], ["Add the missing semicolon"], "Statements end with `;`."),
    "CS0165": E("Flow", "Use of an unassigned local variable (C#).", ["Variable assigned only in some branches"], ["Initialise at declaration"], "Definite assignment analysis."),
    "CS0161": E("Flow", "Not all code paths return a value (C#).", ["Missing return in some branch"], ["Add return/throw to every path"], "Every path of a non-void method must return."),
}

MSG_HINTS = [
    (r"is not a function", "The called value is not a function - it may be undefined, misspelled, or shadowed."),
    (r"cannot read propert(?:y|ies) of (?:undefined|null)", "A property was read from undefined/null - a value was not set or an async result was not awaited."),
    (r"unsupported operand type", "Two operands of incompatible types were combined (e.g. str + int)."),
    (r"object is not subscriptable|not subscriptable", "Indexing was used on something that does not support it (often None or an int)."),
    (r"is not callable", "A non-function was called like a function (a variable may shadow a function name)."),
    (r"has no attribute", "The object does not have that attribute - check for None or a wrong type."),
    (r"invalid literal for int", "Text that is not a whole number was passed to int()."),
    (r"no module named", "The module is not installed in the active environment."),
    (r"connection refused|econnrefused", "Nothing is listening on that host/port, or a firewall blocks it."),
    (r"timed? ?out|etimedout", "The remote service did not answer in time."),
    (r"permission denied|eacces", "The process lacks permission for that file/port."),
    (r"out of memory|outofmemory", "Memory was exhausted - check for unbounded collections or large loads."),
]


def _frames(pattern, text, with_col=False):
    out = []
    for m in pattern.finditer(text):
        d = m.groupdict()
        out.append({"file": d["file"].strip(), "line": int(d["line"]),
                    "function": (d.get("func") or "").strip(), "column": int(d["col"]) if d.get("col") else None})
    return out


def _is_library(path, language):
    p = path.replace("\\", "/").lower()
    return any(x in p for x in ("site-packages", "/lib/python", "<frozen", "node_modules", "node:internal",
                                "/usr/lib/", "system.private")) or \
        (language == "java" and re.match(r"^(java|jdk|sun)\.", path))


def _primary(frames, language, func_names=None):
    if not frames:
        return None
    mine = [f for f in frames if not _is_library(f["file"], language)] or frames
    return mine[-1] if language == "python" else mine[0]


def parse(text):
    text = text.replace("\r\n", "\n")
    lines = [l for l in text.split("\n")]
    res = {"language": "unknown", "error_type": None, "code": None, "message": None, "frames": []}

    if "Traceback (most recent call last)" in text or PY_FRAME.search(text):
        res["language"] = "python"
        res["frames"] = _frames(PY_FRAME, text)
        for l in reversed(lines):
            m = PY_EXC.match(l.strip())
            if m:
                res["error_type"], res["message"] = m.group("type").split(".")[-1], m.group("msg") or ""
                break
        return res

    m = CS_COMPILE.search(text)
    if m:
        res.update(language="csharp", error_type=m.group("code"), code=m.group("code"), message=m.group("msg").strip(),
                   frames=[{"file": m.group("file").strip(), "line": int(m.group("line")), "function": "",
                            "column": int(m.group("col"))}])
        return res
    m = CS_EXC.search(text)
    if m:
        res.update(language="csharp", error_type=m.group("type").split(".")[-1], message=m.group("msg").strip(),
                   frames=_frames(CS_FRAME, text))
        return res

    if JAVA_FRAME.search(text) or re.search(r'Exception in thread|Caused by:', text):
        m = JAVA_EXC.search(text)
        if m:
            res.update(language="java", error_type=m.group("type").split(".")[-1], message=(m.group("msg") or "").strip(),
                       frames=_frames(JAVA_FRAME, text))
            return res

    for l in lines:
        m = JS_EXC.match(l.strip())
        if m:
            res.update(language="javascript", error_type=m.group("type"), message=m.group("msg").strip(),
                       frames=_frames(JS_FRAME, text))
            return res

    for l in lines:
        m = re.match(r'^\s*([A-Za-z_][\w.]*(?:Error|Exception)):?\s*(.*)$', l)
        if m:
            res.update(error_type=m.group(1).split(".")[-1], message=m.group(2))
            break
    return res


def _snippet(frame, sources, ctx=4):
    if not frame or not sources:
        return None
    want = frame["file"].replace("\\", "/")
    base = want.split("/")[-1]
    hit = next((p for p in sources if p.replace("\\", "/").endswith(want)), None) or \
        next((p for p in sources if p.replace("\\", "/").split("/")[-1] == base), None)
    if not hit:
        return None
    src = sources[hit].split("\n")
    n = frame["line"]
    start, end = max(1, n - ctx), min(len(src), n + ctx)
    return {"file": hit, "lines": [{"n": i, "text": src[i - 1], "hit": i == n} for i in range(start, end + 1)]}


def analyze(text, sources=None):
    p = parse(text)
    etype, msg = p["error_type"], p["message"] or ""
    kb = KB.get(etype) if etype else None
    primary = _primary(p["frames"], p["language"])
    snippet = _snippet(primary, sources)

    verified = []
    if p["language"] != "unknown":
        verified.append(f"Format matches a {p['language']} error output")
    if etype:
        verified.append(f"Error type: {etype}")
    if msg:
        verified.append(f"Message: {msg}")
    if primary:
        loc = f"{primary['file']}, line {primary['line']}"
        if primary.get("function"):
            loc += f", in {primary['function']}"
        verified.append(f"Most relevant location in the trace: {loc}")
    if p["frames"]:
        verified.append(f"{len(p['frames'])} stack frame(s) parsed")
    names = re.findall(r"'([^']+)'|\"([^\"]+)\"", msg)
    if names:
        verified.append("Names/values quoted in the message: " + ", ".join(a or b for a, b in names[:4]))
    if snippet:
        hit = next(l for l in snippet["lines"] if l["hit"])
        verified.append(f"Source line {hit['n']} in {snippet['file']}: {hit['text'].strip()}")

    causes = list(kb["causes"]) if kb else []
    for pat, hint in MSG_HINTS:
        if re.search(pat, msg, re.I) or re.search(pat, text, re.I):
            causes.append(hint)
    causes = list(dict.fromkeys(causes))

    return {
        "language": p["language"], "error_type": etype, "message": msg,
        "category": kb["category"] if kb else "Unclassified",
        "explanation": kb["explain"] if kb else "This error type is not in the built-in rule base yet.",
        "verified": verified,
        "possible_causes": causes,
        "suggestions": kb["fixes"] if kb else ["Search the exact message together with the language/framework name",
                                                "Read the first frame that points into your own code"],
        "learning": kb["concept"] if kb else None,
        "location": primary, "frames": p["frames"][:25], "snippet": snippet,
        "confidence": "medium" if kb and primary else ("low" if not kb else "medium-low"),
        "note": "Possible causes are hypotheses based on the error type and message, not proof of the root cause.",
    }
