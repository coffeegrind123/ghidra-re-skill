# Hungarian Notation Reference

## Type Normalization

Always use lowercase Ghidra builtins, not Windows SDK types:

| Windows Type | Ghidra Builtin | Size |
|-------------|----------------|------|
| UINT, DWORD, ULONG | uint | 4 bytes |
| INT, LONG | int | 4 bytes |
| USHORT, WORD | ushort | 2 bytes |
| SHORT | short | 2 bytes |
| BYTE | byte | 1 byte |
| CHAR | char | 1 byte |
| BOOL | bool | 1 byte |
| ULONGLONG | ulonglong | 8 bytes |
| LONGLONG | longlong | 8 bytes |

Use lowercase when calling `set_local_variable_type`, `apply_data_type`, `create_struct`.

## Type-to-Prefix Mapping

| Ghidra Type | Size | Prefix | Local Example | Global Example |
|-------------|------|--------|---------------|----------------|
| byte | 1B | b/by | bFlags, byStatus | g_bInitialized |
| char | 1B | c/ch | cCharacter | g_cDelimiter |
| bool | 1B | f | fIsValid, fEnabled | g_fServiceRunning |
| short | 2B | n/s | nOffset | g_nErrorCount |
| ushort | 2B | w | wStatus, wPort | g_wServiceStatus |
| int | 4B | n/i | nCount, iIndex | g_nActiveConnections |
| uint | 4B | dw | dwFlags, dwTableIndex | g_dwProcessId |
| long | 4B | l | lOffset | g_lFilePosition |
| ulong | 4B | dw | dwValue | g_dwTickCount |
| longlong | 8B | ll | llTimestamp | g_llStartTime |
| ulonglong | 8B | qw | qwBitPattern | g_qwTotalBytes |
| float | 4B | fl | flScale | g_flScaleFactor |
| double | 8B | d | dPowerResult | g_dPiConstant |
| float10 | 10B | ld | ldExtended | g_ldMathConstant |
| void * | 4B | p | pBuffer, pData | g_pSharedMemory |
| \<type\> * | 4B | p\<Type\> | pUnitAny | g_pCurrentPlayer |
| HANDLE | 4B | h | hFile, hThread | g_hRegistryKey |
| byte[N] | NB | ab | abXmmBuffer | g_abEncryptionKey |
| ushort[N] | N*2B | aw | awTableEntries | g_awPortNumbers |
| uint[N] | N*4B | ad | adOffsetTable | g_adPlayerSlots |
| char * | 4B | sz/lpsz | szPath, lpszCmd | g_szConfigPath |
| wchar_t * | 4B | wsz | wszUnicodePath | g_wszDisplayName |
| \<Struct\> | varies | camelCase | unitAny, playerData | g_ServiceStatus |
| Func ptr | 4B | PascalCase | — | ProcessInputEvent |

## Scope Prefix

All globals: `g_` before type prefix (g_dwFlags, g_szPath, g_pMain).

Exception: Read-only string constants may omit `g_` (szErrorMessage).

Function pointers: PascalCase, no `g_` prefix (ProcessInputEvent, ValidatePacket).

## Undefined Type Replacement

| Undefined | Replace With | Based On |
|-----------|-------------|----------|
| undefined1 | byte / char / bool | Usage context |
| undefined2 | ushort / short | Signed vs unsigned |
| undefined4 | uint / int / float / \<type\> * | Usage: arithmetic=int, flags=uint, deref=pointer |
| undefined8 | double / ulonglong / longlong | Float ops=double, else integer |
| undefined1[N] | byte[N] | Byte arrays, XMM spills |
| undefined4[N] | uint[N] | Dword arrays |

## Pointer Types

Always specify complete declaration:
- `void *` not `pointer`
- `char *` not `pointer`
- `UnitAny *` not `pointer`
- `int *` if dereferenced or offset arithmetic

## Workflow

1. `get_function_variables` — discover storage types
2. Normalize: UINT→uint, DWORD→uint, BYTE→byte
3. `set_local_variable_type` for undefined storage
4. `get_function_variables` — verify, discover new SSA vars
5. `rename_variables` with Hungarian prefixes
6. Verify: prefix matches actual type (dw↔uint, w↔ushort, b↔byte)

## Common Mismatches (Must Fix)

```
Type: uint    + Prefix: b   → WRONG (should be dw)
Type: ushort  + Prefix: dw  → WRONG (should be w)
Type: UINT    + any prefix  → WRONG (normalize to uint first)
Type: undefined4 + Prefix: p → WRONG (set actual type first)
```
