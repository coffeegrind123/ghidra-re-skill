# Dynamic / Runtime RE Reference

Static Ghidra analysis tells you *what the code is*; this companion tells you *what it
does when it runs* and **confirms the offsets and behaviors you inferred statically**.
When a static-only pass leaves you stuck — a struct offset you can't fully resolve, a
factory you can't tell returns NULL or an object, a DLL that loads on Windows but
crashes under your harness — these runtime techniques close the loop.

The worked examples below are from driving a real 32-bit Windows game client
(`target.exe` + `engine.dll`) **headless under Wine in a container**, reading/writing its live
memory via `/proc/<pid>/mem`, and replacing crashing native DLLs with clean stubs whose
vtable layout was recovered by RE. The helper tools referenced (a PE rebaser, an RVA
byte-patcher, per-DLL stub builds) are generic and easy to reproduce.

Cross-references:
- [headless-operations.md](headless-operations.md) — the `analyzeHeadless` + Java-`GhidraScript`
  decompile fallback (used here to read vtable dispatches), and Ghidra image-base math.
- [gotchas.md](gotchas.md) — "Live-memory RE: match the EXACT binary the target maps",
  and image-base-relative address math (`RVA = ghidra_addr − image_base`,
  `live_addr = runtime_base + RVA`).
- [data-type-investigation.md](data-type-investigation.md) — Ghidra gives you the struct
  RVA/offsets statically; `/proc/<pid>/mem` reads/writes them live to confirm.

---

## 1. Running Windows binaries headless under Wine

Run a 32-bit Windows app under Wine + a virtual X server (Xvfb) with no GPU and no real
display:

```bash
export WINEPREFIX=/root/.wine WINEARCH=win32 DISPLAY=:99
# Start a virtual framebuffer once (1024x768x24; -nolisten tcp = no network listener):
xdpyinfo -display :99 >/dev/null 2>&1 || \
  { setsid Xvfb :99 -screen 0 1024x768x24 -nolisten tcp </dev/null >/tmp/xvfb.log 2>&1 & sleep 2; }
```

- **Xvfb cannot do 16-bit depth** (and there's no Xephyr/Xvnc in a typical container).
  This is usually irrelevant: if the app draws into an **in-memory DIB surface**
  (`CreateDIBSection`), a 24-bit Xvfb is fine — the bit depth of the offscreen surface is
  independent of the X server.

- **Launch detached — a foreground `docker exec` of a Wine process gets reaped** (~14s,
  exit 137). Use `setsid` + redirect, background it, then poll:

  ```bash
  cd "$GAMEDIR"
  setsid wine target.exe -game <mod> -window -width 640 -height 480 \
    -noip -nojoy -noaudio -insecure -soft </dev/null >/tmp/hl.log 2>&1 &
  ```

  **`</dev/null` is mandatory.** Without it, wine/wineserver inherit the caller's pipe
  (e.g. an `execSync`/`docker exec` stdin) and the process blocks forever on `pipe_read`;
  the launching call never returns.

- **`WINEDLLOVERRIDES="ddraw=n"`** forces a *native* DLL (your stub) to win over Wine's
  builtin (`n` = native, `b` = builtin). Use this whenever you drop a replacement DLL
  whose name collides with a Wine builtin (`ddraw`, `dinput`, …).

- **Pre-clear crash-modal registry flags** so a headless run doesn't block on a
  `MessageBox` no one can dismiss:

  ```bash
  wine reg delete "HKCU\Software\<Vendor>\<Game>\Settings" \
    /v CrashInitializingVideoMode /f >/dev/null 2>&1
  ```

- **App flags can silently disable networking.** A `-noip`-style switch turns off the UDP
  stack entirely: the app reaches a "connecting" state but never sends a packet — looks
  like a server/auth problem but is self-inflicted. Drop the flag when you actually need
  the socket path.

See container/deploy footguns in §7.

---

## 2. WINEDEBUG channels as a dynamic-RE instrument

`WINEDEBUG` is the single most useful runtime lens here — it turns Wine into a tracer for
exceptions, module loads, DllMain results, and (filtered) every API call. Set it in the
launch env (`WINEDEBUG=+seh`, comma-separated for multiple: `WINEDEBUG=+seh,+module`).

### `+seh` — exception triage (primary crash lens)
Prints every dispatched exception with `code=`, `addr=`, `ip=`, `info[0]`, `info[1]`, and
the SEH handler chain.

```bash
WINEDEBUG=+seh ...   then:   grep -aE "code=c0000005|info\[" /tmp/hl.log
```

- `info[0]` = fault kind: **0 = read / execute-fetch**, **1 = write**.
- `info[1]` = the faulting address.
- **Instruction-fetch fault where `addr == ip` and `info[0]=0` on an uncommitted code
  page** = the signature of the **Wine page-commit fault** (see §3) — the DLL's own
  `.text` entry page never got committed.
- **Write fault (`info[0]=1`) to a module's own `.text` / image-base page** = self-modifying
  / anti-tamper code (e.g. Miles `mss32.dll` patches its own code in `DllMain`).
- **Identical register state across crashes in different DLLs ⇒ the same Wine loader code
  path**, not a bug unique to one DLL.

### `+loaddll` — module → base-address map
Prints each module load with its base address. Combine with `/proc/<pid>/maps` to map
runtime addresses ↔ modules, and to feed §3's `ret=` → RVA math (e.g.
`consumer.dll@<runtime_base>` → its PE `ImageBase`; `engine.dll@<runtime_base>`).

### `+module` — DllMain success/failure (catches the silent dependency failure)
Shows `MODULE_InitDLL ... RETURN 0` and `Initialization of L"x" failed`. **A dependency's
`DllMain` returning FALSE makes the importing DLL's `LoadLibrary` fail** — which in a
coarse trace looks *identical to a clean exit*. Misreading this as "the engine exited
normally at video init" cost an entire session; always run `+module` when a load
mysteriously "succeeds then exits."

### `+relay` — per-call API trace, FILTERED to one DLL
`+relay` alone is far too noisy. Filter it to a single DLL via the registry, then it
becomes a precise "did execution reach API X?" probe:

```bash
wine reg add 'HKCU\Software\Wine\Debug' /v RelayInclude /d 'gdi32.dll' /f
WINEDEBUG=+relay ...                        # run, capture log
wine reg delete 'HKCU\Software\Wine\Debug' /v RelayInclude /f   # ALWAYS remove after
```

Reading the filtered trace as behavioral signal:
- `CreateDIBSection` in the trace = code reached its GDI memory-framebuffer path.
- `RegisterClassExW` / `CreateWindowExW` from a given module base = it reached window
  creation (and from *which* module — check the `ret=` caller).

Remove the `RelayInclude` value afterward; relay tracing slows everything dramatically.

### Pinpointing the crashing function inside a Wine builtin
Take the faulting `ip`, subtract the builtin's load base (from `+loaddll`), then
disassemble the builtin at that offset:

```bash
i686-w64-mingw32-objdump -d .../wine/i386-windows/ntdll.dll   # then find ip − base
```

A crash in ntdll's import resolver (`_import_dll`, e.g. `movzx edx,WORD PTR [ebx]` with
`ebx = base + bad_name_rva`) means an import table landed on an uncommitted page — often
a downstream symptom of §3's reservation/relocation collisions.

### Finding the CALL SITE of a "call through garbage pointer" crash
`+seh` gives you the faulting `ip` (the garbage TARGET, e.g. `addr=0x0D439C61` not in any
module), but not WHO called it. Three ways to get the caller, in order of preference:

1. **Stub trap-log (best when the bad call goes through a stub vtable).** If the garbage call
   is a vtable method on a clean stub (§3), give every unimplemented slot a trap that logs
   `__builtin_return_address(0)`:
   ```c
   static int __attribute__((thiscall)) vtbl_trap(void *self){
       slog_hex("TRAP method ret=", (unsigned)(unsigned long)__builtin_return_address(0));
       return 0; }
   ```
   The last log lines before the crash give the **exact caller RVA** in the consumer DLL.
   A tail-jmp thunk (`mov ecx,[ecx+0x78]; mov eax,[ecx]; jmp [eax+N]`) preserves the original
   return address, so the logged ret is the thunk's *caller*, and `N` is the vtable offset.
2. **ptrace SIGSEGV tracer (no gdb needed; container needs `CAP_SYS_PTRACE`).** A 64-bit Python
   `ctypes` tracer SEIZEs all `/proc/<pid>/task/*` tids and catches the SIGSEGV. For a 32-bit
   Wine tracee the kernel maps the i386 regs into the x86_64 `user_regs_struct`, so `regs.rip`
   == `eip`, `regs.rsp` == `esp`. Read `[esp]` (= the `call`'s return address = call site) and
   scan the stack for module-mapped values. `PTRACE_SEIZE=0x4206`, `__WALL=0x40000000`,
   `PTRACE_GETREGS=12`; pass benign segvs through with `PTRACE_CONT(sig)`, capture the fatal
   one. Note: Wine synthesizes *software* exceptions (RaiseException / OutputDebugString,
   `code=40010006`) without a real SIGSEGV, so a SIGSEGV tracer only stops on genuine faults.
3. **objdump the consumer DLL** at the call-site RVA: `i686-w64-mingw32-objdump -d
   --start-address=<va> --stop-address=<va2> consumer.dll.orig` (PE VAs are ImageBase+RVA).
   Count the `push`es before the `call [reg+N]` to get the arg count → the required `ret N`.

> **winedbg JIT is NOT usable for legacy-engine-class engines.** Setting AeDebug `Debugger=winedbg
> --auto %ld %ld` + `Auto=1` makes winedbg break on the engine's *benign first-chance* SEH
> exceptions during init → boot never completes. Disable it (`Auto=0`) and use the three
> methods above. `winedbg --auto` as a launcher also silently fails here.

---

## 3. The "Wine page-commit fault" and the clean-DLL-stub methodology

**Symptom.** A native Windows DLL that loads fine on real Windows faults under Wine at a
*fixed RVA* when loaded beside other relocated DLLs: an instruction-fetch on an
uncommitted `.text` page (`+seh`: `info[0]=0`, `addr==ip`), and/or a write to its own
image-base page (`info[0]=1`). It is often **flaky** (load-address-dependent — succeeds
intermittently). Marking `.text` writable (RWX) sometimes removes the fault by forcing the
page commit, but then **breaks IAT binding** → a new exec fault in the `.rdata`/IAT region
→ dead end.

**Robust fix: replace the problem DLL with a clean stub.** A stub with a trivial
`DllMain{ return TRUE; }`, KERNEL32-only dependencies, no relocation / anti-tamper /
packing, exporting exactly the symbols the consumer imports, has no page to fail to commit
and loads deterministically. Proven 6× in a real RE project: `mss32`, `ddraw`, `SDL2`,
`steam_api`, `htmlctl` (and the wined3d-reservation that `ddraw` pulled in). Stubs live
in `<name>-stub/` with a `build.sh`; deploy each over the game-dir DLL with
`docker cp` (§7).

### Confirming relocation is the trigger — and rebasing as an alternative fix
The fault fires *because the DLL relocated*, so the fastest confirmation is purely runtime —
no Ghidra needed. Snapshot a live (or about-to-crash) process and compare each module's load
address to its preferred `ImageBase`:

```bash
p=$(pgrep -x <target>.exe | head -1)
for d in a.dll b.dll c.dll; do
  base=$(grep -i "/$d\$" /proc/$p/maps | head -1 | cut -d- -f1)
  echo "$d loaded @0x$base"        # != PE ImageBase  => RELOCATED  => fault candidate
done
```

Cross-check the PE header for *why* they relocate — two causes, both visible statically:
- **Shared preferred base.** Read each DLL's `ImageBase` (optional-header +0x1c for PE32). When
  several DLLs all prefer the SAME base (a common pattern when a family of related modules ships
  with one default base), only one wins; the rest relocate. A short `python3` over the PE headers
  finds the collision set.
- **`DYNAMICBASE`.** `DllCharacteristics` (optional-header +0x46) bit `0x40` = ASLR — the loader
  relocates that module **every launch** regardless of collisions. These are the most volatile.

**The crash is concurrency-amplified**: a single launch may relocate cleanly many times in a row,
but running N processes that relocate the same DLLs *simultaneously* spikes the page-commit-fault
rate. So "it boots fine solo" does NOT clear a relocating-DLL theory — reproduce under the real
concurrency.

**Alternative fix when you can't stub it** (you need the DLL's real behavior, not a no-op):
**rebase the file** to a distinct fixed base + clear `DYNAMICBASE`, so the loader maps it at its
preferred base with **no relocation** → no fault. This is a PE rewrite (apply `.reloc` fixups,
rewrite `ImageBase`, clear the `DYNAMICBASE` bit). Assign each colliding DLL its own slot in a
free address window. Verify post-fix: re-snapshot `/proc/maps` — every rebased DLL now sits at
its fixed base and the old relocation range is empty. **Integrity caveat:** rebasing changes the
file bytes, so if a peer/server checksums the file you must arrange for the *original* checksum to
be reported (e.g. keep a pristine copy and hook the engine's hash routine to read it).

### Build & export decoration
Build with mingw, `--kill-at` for **undecorated cdecl** exports:

```bash
i686-w64-mingw32-gcc -m32 -O2 -shared -o htmlctl-stub.dll htmlctl_stub.c \
  -Wl,--kill-at -lkernel32
```

**Emitting an exact `name@N` stdcall-decorated export** (the consumer imports the
Watcom/MSVC-decorated name, e.g. `_AIL_startup@0`):
- `.def` files **cannot** express `name@N` — the `.def` parser treats `@N` as an ordinal.
- `.drectve -export:` mangles the `@`.
- The trick that works: give the C symbol a **double** leading underscore via an `asm()`
  label, then let `ld --export-all-symbols` strip *one* underscore, yielding the exact
  decorated name. `__stdcall` codegen still emits the correct callee-cleanup `ret N` from
  the param list. From `mss32-stub/stub.c`:

  ```c
  #define AIL(sym, params, ...) \
    int __stdcall sym params asm("_" #sym "@" #__VA_ARGS__); \
    int __stdcall sym params { return 0; }
  /* yields export "_AIL_startup@0", "_AIL_open_digital_driver@16", ... */
  AIL(_AIL_startup,             (void),                   0)
  AIL(_AIL_open_digital_driver, (int a,int b,int c,int d), 16)
  ```

### Stubbing a COM-ish / vtable-interface DLL
Some DLLs hand the consumer a C++-style object via a `CreateInterface(name)` factory; the
consumer then calls vtable slots and **often derefs the result with no NULL check** — so
returning NULL from the factory crashes the consumer. You must return a *real* object
whose vtable has working slots. The discipline (from `{steam,htmlctl}-stub/`):

1. **Implement every actually-invoked slot with the CORRECT callee-cleanup `ret N`** via
   `__attribute__((thiscall))` — `N = stack-arg-bytes` (1 stack arg → `ret 4`, 2 → `ret 8`,
   …). A **wrong N silently corrupts the stack**; you won't get a clean error.
   ```c
   #define THISCALL __attribute__((thiscall))
   static int THISCALL Ctrl_Init(void *self, const char *cacheDir, const char *cookiePath)
   { return 1; }                          /* vtable[0x4], 2 stack args -> ret 8 */
   ```
2. **Fill every *other* slot with a logging "trap"** that records its caller and returns 0,
   so the first time a real method fires it shows up as a log line to implement — instead
   of a silent crash:
   ```c
   static int THISCALL vtbl_trap(void *self) {
       slog_hex("[stub] TRAP method, ret=",
                (unsigned)(unsigned long)__builtin_return_address(0));
       return 0;
   }
   /* in DllMain: init all VT_SLOTS to &vtbl_trap, then overwrite the known ones */
   ```
   > ⚠️ **The catch-all trap is a latent stack-corruption bug for any trapped slot that takes
   > args.** `vtbl_trap(void *self)` cleans **0 bytes** (`ret 0`), correct ONLY for 0-arg
   > methods. If a method WITH stack args lands on the trap, it leaks those bytes → the stack
   > corrupts. One leak is often survivable, so it hides: the stub "works" through boot and on
   > most servers, then a *different input path* (e.g. a server that pushes an HTML MOTD) fires
   > a trapped 2-arg slot repeatedly across reconnect cycles → the leaks accumulate → a call
   > through a garbage pointer (`call 0x0D4…` / `EIP=0`) far from the real cause. **Fix = give
   > that slot the correct `ret N` (implement it; the body can still just `return 0` — it's the
   > cleanup, not the return value, that matters). Don't "fix" it by returning a fat object
   > unless the consumer needs one — a non-NULL return makes the consumer drive THAT object
   > through more arg-taking traps and moves the crash.** A generic trap cannot self-correct its
   > `ret N`, so every arg-taking slot that ever fires must be implemented individually.
3. The factory returns a small object `{ const void **vtbl; }` pointing at that table.

**The iteration recipe** (enumerate-and-implement, one slot per cycle):
1. Run; read the stub log's `TRAP … ret=0xADDR` lines and the `+seh` `c0000005` address.
2. `ret=` is a return address **in the calling DLL**. Subtract that DLL's load base
   (from `+loaddll`) → RVA, then add the DLL's **ImageBase** → the objdump/Ghidra address.
3. Disassemble the caller and look at the instruction **just before** the ret addr:
   `call DWORD PTR [edx+0xNN]` gives the **vtable byte-offset** (`0xNN`); count the
   `push`es since `mov edx,[obj]` for the **arg bytes** (= `ret N`; ignore pushes belonging
   to nested calls). For big callers, the Ghidra-headless decompile fallback in
   [headless-operations.md](headless-operations.md) renders this as
   `(**(code **)(*obj + 0xNN))(args)` — read `0xNN` and the arg count directly.
4. Implement that slot (`THISCALL`, correct `ret N`), wire it into the vtable in `DllMain`,
   `build.sh`, `docker cp`, relaunch. Repeat until the consumer stays alive.

Real worked stubs: `{mss32,ddraw,sdl2,steam,htmlctl}-stub/`.

---

## 4. Live memory RE via `/proc/<pid>/mem` (no debugger)

With `cap_add SYS_PTRACE` on the container, you can **read and write** a live process's
memory directly through `/proc/<pid>/mem` plus a tiny Python `struct` script — no debugger,
no remote thread, no Cheat Engine. This is the runtime complement to Ghidra's static
offsets: Ghidra gives you the RVA, `/proc/<pid>/mem` reads/writes it live.

**Resolve the live module base** from `/proc/<pid>/maps`, then `seek(base + RVA)`:

```bash
docker exec rc-test bash -lc '
p=$(for q in $(pgrep -f target.exe); do
      grep -qi engine.dll /proc/$q/maps 2>/dev/null && echo $q && break; done)
b=$(grep -i engine.dll /proc/$p/maps | head -1 | cut -d- -f1)
python3 -c "import struct;m=open(\"/proc/$p/mem\",\"rb\");
m.seek(0x$b+0x9EEDE0);print(\"cls.state=\",struct.unpack(\"<I\",m.read(4))[0])"'
```

- **Pick the RIGHT process when several share a name.** Don't trust the first `pgrep` hit:
  choose the PID whose `/proc/<pid>/maps` actually contains the **target module**
  (e.g. `engine.dll`), and **skip zombies** (`/proc/<pid>/stat` state `Z`) — a non-`--init`
  PID 1 leaves dozens of defunct wine procs that pollute `pgrep` (see §7).
- **Reading a state enum:** `seek(base + cls.state RVA)`, unpack `<I`. In this engine
  `cls.state` runs 1=disconnected(menu) … 5=ca_active.
- **Injecting a command with no API:** the engine's command buffer is a sizebuf
  (`data` ptr at `+0x8`, `maxsize` `+0xC`, `cursize` `+0x10`). Append your command bytes
  at `data_ptr + cursize`, then **bump `cursize`** — the engine's `Cbuf_Execute` drains it
  next frame. This drives the live program entirely from outside.
- **Always match the EXACT binary the process maps.** Offsets from a same-named local copy
  are garbage against a different build (all-zero reads at a plausible base usually mean
  wrong-binary or pre-init, not wrong math). See
  [gotchas.md](gotchas.md) "Live-memory RE: match the EXACT binary the target maps".

---

## 5. Network-level RE with tcpdump

When the unknown is a binary's **network behavior**, watch the wire instead of the code.

```bash
tcpdump -i any -n host <server-ip>          # sizes / direction / rate
```

- **Read the pattern, not just payloads.** A steady small-out / large-in fragment loop =
  an active download *or* a stuck re-request loop. A connecting client that sends nothing =
  the `-noip`-style networking-disabled trap (§1), not a server problem.
- **Surface plaintext protocol tokens:**
  ```bash
  tcpdump -i any -A host <ip> | grep -aoE '[ -~]{4,}' | sort | uniq -c | sort -rn
  ```
  reveals connectionless commands, filenames, version strings. (`-X` for hex+ASCII.)
  **Caveat:** encrypted/compressed netchan payloads won't be readable — only the
  connectionless/handshake portion is.
- **Prove reachability independently of the binary.** A small Python UDP probe (e.g. a
  game's A2S query) confirms the *server* is up and answering, separating "server is
  unreachable" from "the binary isn't sending."

---

## 6. PE surgery for RE (rebasing / patching)

Two recurring needs: rebase a DLL to a free preferred base (so Wine loads it WITHOUT
relocation, dodging the relocation-EH crash class), and byte-patch code by RVA. Both have a
sharp pefile footgun.

### Rebasing — do NOT use `pefile.relocate_image()` + `pefile.write()`
`pefile.write()` re-serializes the import directory and rewrites the **ILT
(OriginalFirstThunk)** entries as `newbase + IAT_rva` — i.e. a VA where the loader expects
an **RVA**. At load the loader double-adds the base → crash at `~2*base + rva` (the
notorious `+0x39068`-style crash). `.reloc` has **zero** fixups in the IAT/ILT range, so
this is pefile mangling, not a legitimate relocation.

**Correct approach: a hand-rolled reloc applier** that touches only `.reloc`
`IMAGE_REL_BASED_HIGHLOW` targets (RVA→file-offset via the section table), leaves ILT/IAT
untouched, clears `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (0x40), and zeroes the stale
Authenticode (SECURITY) data-directory entry. Real tool: `rebase-dll.py`
(cross-validated **byte-for-byte vs pefile** everywhere except the import dir pefile
corrupts; it even asserts that **0** reloc fixups land in the IAT before writing).

```bash
rebase-dll.py SDL2.dll 0x28000000 SDL2-rebased.dll
```

### Byte-patching by RVA
For the `.text`/`.rdata` of these DLLs, **RVA == file offset** (verified:
`.text` RVA 0x1000, raw 0x1000) — but still resolve RVA→file-offset via the section table
to be safe (`pefile.get_offset_from_rva`, or the inline section walk in the tool). Real
tool: `patch-swdll.py`:

```bash
# NOP a 2-byte JZ at RVA 0xA3364, and force "MOV AL,1; RET 4" at 0xA5830:
patch-swdll.py engine.dll.orig engine.dll 0xA3364=9090 0xA5830=B001C20400
```

Note: NOP-ing return checks to force a "success" can leave the object **inconsistent**
(faked success with no surface/dims) → downstream chokes. Patch the data the code needs,
don't just bypass the guard.

---

## 7. Container / deploy gotchas (each cost real time)

- **9p mount (WSL ↔ Windows): in-container `cp` into a bind-mounted dir does NOT reliably
  persist**, and reads see stale bytes. **Deploy with `docker cp host→container`**, and
  always re-verify the deployed file's PE ImageBase/size afterward. (The repo bind mounts
  must use the Windows path `//c/users/...`, never `./` — see the project `CLAUDE.md`.)
- **Make the harness container PID 1 a real init: `docker run --init`** (tini). Otherwise a
  `sleep infinity` PID 1 never reaps the wine children and you accumulate 70+ zombies that
  pollute `pgrep` — then §4's process-pick must skip `state==Z` entries.
- **Long `docker exec` jobs get reaped (exit 137).** Run downloads / long polls **detached**
  (`docker exec -d …`, or `setsid … &`), writing to a file, then poll the file — same
  reason as §1's detached launch.
