# Plugin X-Ray

**What can this plugin actually do, before I load it?**

BOSS plugins are JARs that run inside the app with the user's rights. The local-testing guide tells you to
copy a JAR into `~/.boss/plugins`, and the host's own docs say plugin access is gated "by choosing which
plugins are allowed". Nothing tells you what a given JAR reaches for. Plugin X-Ray does.

It reads a JAR's compiled classes **without loading or running anything** and reports the capabilities they
reference: starting processes, opening connections, listening on ports, writing or deleting files, reading the
environment, loading native or dynamic code, and each sensitive host API (secret vault, brokered credentials,
authenticated backend proxy, the ungated project rewrite, the ungated event bus, ...).

It is a service plugin that exposes four **read-only** MCP tools to the agent already connected to BOSS:

| Tool | What it does |
|---|---|
| `xray_scan_jar` `{path}` | Full report for one local `.jar`: capabilities with evidence, findings, hosts named in the code, SHA-256, and the scan's limits. |
| `xray_diff_jars` `{old_path,new_path}` | What the newer build **gained or dropped**: capabilities, hosts named in the code, findings, `requiredPermissions`. Compared by capability id, so moving a call between classes is not a change. Use it before loading an update or after a rebuild. |
| `xray_scan_installed` | Scans every JAR in `~/.boss/plugins`: risk ranking, more than one JAR for one plugin id, and leftover `.jar.sig` files. |
| `xray_capabilities` | Lists every capability it recognises, its risk and why it matters. |

`xray_scan_jar` and `xray_diff_jars` take an optional `format: "json"` for a CI step or an agent that wants fields
instead of prose (for example: fail the build when `topRisk` is `HIGH`, or when `addedRisk` is not `INFO`).

## An example finding

```
X-RAY  boss-plugin-example-1.0.0.jar
  plugin   ai.rever.boss.plugin.dynamic.example  v1.0.0  (type panel, api 1.0.20)
  verdict  REVIEW BEFORE LOADING - high-risk capabilities found

Capabilities (highest risk first)
  [HIGH] host.project-replace - Rewrites files across the open project
      why: ProjectSearchProvider.replaceInProject is ungated: no permission stands between a plugin and the write.
Findings
  [HIGH] combo.secret-and-network - Can read credentials and reach the network
  [MEDIUM] manifest.ungated-sensitive-api - Uses a sensitive host API but declares no requiredPermissions
  [MEDIUM] sig.stale - The .jar.sig is older than the JAR
Limits
  - Static scan of 41 class constant pool(s); code loaded or built at run time is not visible.
```

Beyond capabilities it checks the things the local-testing guide warns about by hand: a **stale `.jar.sig`**
(the host hard-fails a load when a leftover signature meets new bytes), **two JARs for one plugin id**, and a
`.jar.sig` with no JAR.

## What it does not claim

- **It never says "safe".** The best verdict is "no risky capabilities found in the constant pools", followed by
  the limits. Static analysis cannot see code that is built or loaded at run time, and it does not open nested
  JARs or analyse native libraries. Those are reported as findings, and the limits are printed on every report.
- **A capability is a reference, not a proof.** A class that mentions `Runtime.exec` may never call it. The report
  says where it was seen so a person can look.
- The risk ranking is a judgement. Each capability carries the reason it matters, and the reasons for the host
  APIs come from what the host itself documents about them.

## Safe by construction

The input is a stranger's file, and the scanner is written accordingly:

- **Bounded reads.** Caps on the JAR (256 MB), entries (20,000), one class (8 MB) and total bytes, none of which
  trusts the sizes the archive declares for itself, so a small JAR that inflates enormously is skipped, not held.
- **A parser that cannot crash.** The class reader reads only the constant pool, bounds-checks every index and
  length, and ends in a clean "malformed" result for truncated, lying or random input (every truncation of a real
  class and thousands of randomly damaged ones are tested).
- **Nothing it prints can forge a line.** Every name from inside a JAR (plugin id, class, host, file name) is
  escaped before it reaches a terminal or an agent.
- **A path argument is checked before the file system is touched.** On Windows, the first `stat` of
  `\\host\share\x` makes the OS authenticate to `host`, so network paths are refused from their text alone.
- **Read-only, and it uses none of what it reports.** It asks the host for no provider, declares
  `readOnly = true` on every tool, and **passes its own scan**: a test scans the plugin's classes and fails if
  they reference anything beyond registering tools and reading files.
- **The catalogue cannot drift from the API.** Tests check that every host type and `PluginContext` getter it names
  exists in the real plugin API jar, so a rename shows up as a failing build rather than a silent blind spot.

## An example update diff

```
X-RAY DIFF
  old      ai.rever.boss.plugin.dynamic.example v1.0.0  (example-1.0.0.jar, sha256 3f9a1c0b7d21)
  new      ai.rever.boss.plugin.dynamic.example v1.1.0  (example-1.1.0.jar, sha256 c41e88a2f0d5)
  verdict  REVIEW BEFORE LOADING - the newer build gained high-risk capabilities

Capabilities GAINED (2)
  [HIGH] process.exec - Runs other programs
  [MEDIUM] net.client - Opens outbound network connections

Hosts newly named in the code (1)
  telemetry.example.test
```

## Verified against the host

Beyond this repo's own tests, the built JAR was run through the BOSS host's code (current `dev`, host API 1.0.93):

- `PluginValidator.validate` (what `boss plugin validate` runs): all 12 checks pass, including the manifest contract, the
  `apiVersion` gate and "entrypoint implements `ai.rever.boss.plugin.api.Plugin`".
- `BinaryCompatibilityValidator.validate` against the host's real API classes: compatible, no errors.
- `DynamicPluginLoaderImpl.loadPlugin` (the host's real loader and `PluginClassLoader`): state `LOADED`; `register` exposed the four
  tools, all read-only; and calling `xray_scan_jar` from inside the host's plugin class loader returned a correct report.

Not done: launching the full BOSS app (that needs a signed-in account). Everything up to the UI and sign-in is the
host's own code.

## Try it (the manual path from the local-testing guide)

```bash
./gradlew buildPluginJar        # build/libs/boss-plugin-xray-0.1.0.jar
```

Quit BOSS, copy that JAR into `~/.boss/plugins/`, relaunch, and enable the tools under **Toolbox > MCP**. Then ask
your agent:

```text
Call xray_scan_jar with {"path": "/absolute/path/to/some-plugin.jar"}
Call xray_scan_installed
```

To iterate without restarting, use `evolver_hot_reload` with this plugin's id
(`ai.rever.boss.plugin.dynamic.xray`) and the new JAR path.

## Develop

```bash
# the plugin API is compile-only; fetch the version you target (the repo's CI does the same):
gh release download v1.0.93 --repo risa-labs-inc/boss-plugin-api --pattern "boss-plugin-api-1.0.93.jar" --dir deps
./gradlew test
```

`./gradlew test` also builds the plugin JAR and **loads it in an isolated class loader that sees only the JDK,
Kotlin, coroutines and the plugin API**, calls `register`, and checks that it asks the host for nothing but the
tool registration. Unit tests running against compiled directories cannot catch a class missing from the JAR;
that one can.

Layout: `ClassFileReader` (constant pool), `CapabilityCatalog` (what each reference means), `JarScanner`
(bounded archive walk and findings), `Report` (text and the installed-plugins summary), `Diff` and `JsonReport`
(update comparison and machine-readable output), `ToolPaths` (argument checks), `XrayMcpTools` and `XrayDynamicPlugin` (the wiring), `MiniJson` and `SafeText` (small helpers).
