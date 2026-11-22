# Function list exchange format (`ida-mcp-funcs`, version 1)

`export_func_list` writes and `import_func_list` reads this JSON document. It
exists so two databases, for example IDA and Ghidra, can be kept in sync in one
call instead of thousands of single renames. A tool on the other side only has
to read and write this schema.

## Document

```json
{
  "format": "ida-mcp-funcs",
  "version": 1,
  "image_base": "0x400000",
  "processor": "metapc",
  "bitness": 64,
  "count": 2,
  "functions": [
    {
      "start": "0x401000",
      "end": "0x401042",
      "name": "parse_header",
      "user_name": true,
      "comment": "validates magic + version",
      "repeatable_comment": "returns 0 on success",
      "flags": {"noreturn": false, "thunk": false, "lib": false}
    },
    {
      "start": "0x8010",
      "end": "0x8014",
      "name": "sub_8010",
      "user_name": false,
      "flags": {"noreturn": false, "thunk": false, "lib": false},
      "thumb": true
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `format` | yes on import (when present, must be `ida-mcp-funcs`) | Format tag. |
| `version` | no (defaults to 1) | Import rejects versions newer than it supports. |
| `image_base` | no | Base address of the exporting database. With `rebase="auto"` (the default), import shifts every address by `current_base - image_base`. |
| `processor`, `bitness` | no | Informational only. |
| `count` | no | Informational only. |
| `functions[]` | yes | One entry per function. |

### Function entry

| Field | Required | Meaning |
|---|---|---|
| `start` | yes | Entry address: hex string (`"0x401000"`) or integer. |
| `end` | no | Exclusive end address. If omitted, IDA infers the end from flow. |
| `name` | no | Function name. |
| `user_name` | no (default `true`) | `false` marks an auto-generated name (`sub_401000`, `FUN_00401000`). Import does not apply names marked `false`. |
| `comment` | no | Function comment (non-repeatable). |
| `repeatable_comment` | no | Repeatable function comment. |
| `flags` | no | Any of `noreturn`, `thunk`, `lib`, each a bool. Missing keys are left alone. |
| `thumb` | no | 32-bit ARM only. `true` means Thumb and `false` means ARM. It is applied over `[start, end)` before the function is created. |

## Import semantics

Each entry is processed in this order:

1. **Instruction set.** On 32-bit ARM, `thumb` sets the T segment register over the range, so the code decodes correctly before the function is defined.
2. **Existence.** A missing function is created (`create_missing=true`). A `start` that falls inside another function is an error, because import never creates overlapping functions. With `update_bounds=true`, an existing function's end is moved to match `end`.
3. **Flags.** `noreturn`, `thunk` and `lib` are applied when `apply_flags=true`. Callers of functions whose `noreturn` changed are re-analyzed once at the end.
4. **Name.** Applied when `user_name` is not `false`. A name the user set in this database is kept unless `overwrite_names=true`. Auto names are always replaced. A name already used elsewhere is reported as an error for that entry.
5. **Comments.** Existing comments are kept unless `overwrite_comments=true`.

New functions are then re-analyzed together. `dry_run=true` reports the same counts without changing anything. The result gives counts (`created`, `bounds_updated`, `renamed`, `commented`, `flags_changed`, `thumb_set`, `skipped`, `failed`) and up to 200 per-entry errors.

For large lists, pass `path` to both tools so the document goes through a file instead of the RPC payload. Run big imports via `submit_job` so the request doesn't time out.

## Mapping notes for a Ghidra implementation

- Write addresses as absolute addresses in the program's address space, as hex strings.
- `noreturn` corresponds to `Function.hasNoReturn()` / `setNoReturn()`, and `thunk` to `Function.isThunk()`.
- `user_name`: emit `false` for `SourceType.DEFAULT` names and `true` otherwise.
- `thumb`: the `TMode` context register in Ghidra.
- `comment` corresponds to the plate comment and `repeatable_comment` to the repeatable comment. The pairing is a convention, so use whatever both sides agree on.
