#!/usr/bin/env python3
"""
clidescribe.py - shared convention so any argparse-based CLI tool can
describe itself as JSON: name, description, and every argument's flags,
type, choices, default, help text, and whether it's positional/repeatable.

This is the common "API" a generic web UI (or any other driver) can rely on
to build a form for a tool it has never seen before, and to know how to
invoke it afterwards -- without that tool needing any web-specific code.

Usage in a tool script:

    import clidescribe

    def build_parser():
        parser = argparse.ArgumentParser(...)
        parser.add_argument(...)
        ...
        clidescribe.add_describe_flag(parser)
        return parser

    def main():
        parser = build_parser()
        if clidescribe.maybe_describe(parser):
            return
        args = parser.parse_args()
        ...

Then, from anywhere (a shell, a web app, another script):

    python3 tool.py --describe

prints the JSON schema and exits, without running the tool's real logic or
requiring any of its normally-mandatory arguments to be supplied.
"""
import argparse
import base64
import json
import sys

DESCRIBE_FLAG = "--describe"
IMAGE_MARKER_BEGIN = "##CLIDESCRIBE-IMAGE-BEGIN##"
IMAGE_MARKER_END = "##CLIDESCRIBE-IMAGE-END##"


def _field_type(action):
    """Map an argparse action to a simple type name a web UI can render."""
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
        return "boolean"
    if action.choices:
        return "enum"
    if action.type is int:
        return "integer"
    if action.type is float:
        return "number"
    return "string"


def build_schema(parser, name=None):
    """Introspect an argparse.ArgumentParser and return a JSON-serializable
    dict describing it: {name, description, arguments: [...]}."""
    arguments = []
    for action in parser._actions:
        if isinstance(action, (argparse._HelpAction, argparse._VersionAction)):
            continue
        if getattr(action, "_clidescribe_internal", False):
            continue

        positional = len(action.option_strings) == 0
        multiple = action.nargs in ("*", "+") or (
            isinstance(action.nargs, int) and action.nargs > 1
        )
        default = action.default
        if default is argparse.SUPPRESS:
            default = None

        entry = {
            "name": action.dest,
            "flags": list(action.option_strings),
            "positional": positional,
            "type": _field_type(action),
            "multiple": multiple,
            "required": bool(getattr(action, "required", False)) and not positional,
            "default": default,
            "help": action.help or "",
        }
        if action.choices:
            entry["choices"] = list(action.choices)
        arguments.append(entry)

    return {
        "name": name or parser.prog,
        "description": parser.description or "",
        "arguments": arguments,
    }


def add_describe_flag(parser):
    """Register --describe on the parser so it shows up in --help and so
    normal parsing doesn't choke on it. The actual describe/exit behavior
    is handled by maybe_describe(), which must be called *before*
    parser.parse_args() (see module docstring) -- argparse itself would
    otherwise reject `--describe` alone if other arguments are required.
    """
    action = parser.add_argument(
        DESCRIBE_FLAG,
        action="store_true",
        help="print a JSON description of this tool's arguments and exit",
    )
    action._clidescribe_internal = True
    return parser


def hide_from_schema(action):
    """Mark an argparse action to be omitted from build_schema() (and thus
    from any auto-generated web form), while it keeps working normally on
    the command line. Use this for CLI-only conveniences that don't make
    sense as a form field -- e.g. a "list valid choices and exit" flag when
    the choices already show up in an enum dropdown.

        action = parser.add_argument("--protocols", action="store_true", ...)
        clidescribe.hide_from_schema(action)
    """
    action._clidescribe_internal = True
    return action


def maybe_describe(parser, argv=None, name=None):
    """Call right after building the parser, before parser.parse_args().

    If --describe is present on the command line, prints the JSON schema to
    stdout and returns True (the caller should stop, e.g. `return` or
    `sys.exit(0)`). Otherwise returns False and the caller proceeds with its
    normal parser.parse_args() flow.
    """
    argv = sys.argv[1:] if argv is None else argv
    if DESCRIBE_FLAG in argv:
        print(json.dumps(build_schema(parser, name=name), indent=2))
        return True
    return False


def build_argv(schema, values):
    """Turn a dict of {argument_name: value} into a CLI argv list, using a
    schema produced by build_schema(). This is the inverse operation a web
    UI (or any other caller) uses to actually invoke the tool after the
    user filled in the generated form.

    - boolean fields: included as a bare flag when truthy, omitted otherwise.
    - positional + multiple: value may be a list, or a string that gets
      split on newlines/commas; each item becomes its own argv entry.
    - flag fields: rendered as `<preferred-flag> <value>`, using the longest
      "--xxx" option string available.
    - empty/None values are skipped entirely (so optional args stay unset
      and defaults apply).
    """
    positionals = []
    flags = []

    for arg in schema.get("arguments", []):
        name = arg["name"]
        if name not in values:
            continue
        value = values[name]
        if value is None or value == "" or value == []:
            continue

        if arg["positional"]:
            if arg["multiple"]:
                if isinstance(value, str):
                    items = [v.strip() for v in value.replace(",", "\n").splitlines() if v.strip()]
                else:
                    items = [str(v) for v in value]
                positionals.extend(items)
            else:
                positionals.append(str(value))
            continue

        flag = next((f for f in arg["flags"] if f.startswith("--")), arg["flags"][0])
        if arg["type"] == "boolean":
            if value in (True, "true", "on", "1", 1):
                flags.append(flag)
        else:
            flags.append(flag)
            flags.append(str(value))

    return flags + positionals


def emit_image(data, mime="image/png"):
    """Print `data` (raw image bytes) to stdout wrapped in a marker a web UI
    can recognize and render as an <img>, instead of dumping binary/base64
    into the plain-text console output. Any clidescribe-based tool can call
    this -- it's a general convention, not specific to one tool.

        png_bytes = page.screenshot()
        clidescribe.emit_image(png_bytes)
    """
    encoded = base64.b64encode(data).decode("ascii")
    print(IMAGE_MARKER_BEGIN)
    print(f"data:{mime};base64,{encoded}")
    print(IMAGE_MARKER_END)


def extract_image(output):
    """Inverse of emit_image(): pull the first image data URI out of a
    tool's captured stdout/stderr, returning (remaining_text, data_uri_or_None).
    Used by the web UI to separate console text from an image to render.
    """
    begin = output.find(IMAGE_MARKER_BEGIN)
    if begin == -1:
        return output, None
    end = output.find(IMAGE_MARKER_END, begin)
    if end == -1:
        return output, None

    data_uri = output[begin + len(IMAGE_MARKER_BEGIN):end].strip()
    remaining = (output[:begin] + output[end + len(IMAGE_MARKER_END):]).strip()
    return remaining, data_uri
