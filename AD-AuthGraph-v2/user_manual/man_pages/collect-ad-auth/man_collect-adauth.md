# COLLECT-ADAUTH(1)

## NAME

**collect-adauth** — high-performance Active Directory authorization state collector (native .NET implementation)

## SYNOPSIS

```
dotnet run --project source/ -- [OPTIONS]
```
or, once published as a self-contained executable:
```
collect-adauth.exe [OPTIONS]
```

## DESCRIPTION

**collect-adauth** is the C#/.NET 8 implementation of the AD-AuthGraph-v2 authorization state collector (source: `source/Program.cs`). It connects directly to Active Directory over LDAP using `System.DirectoryServices.Protocols`, walks the directory using paged, streaming queries, and produces a single JSON **authorization state** file describing users, groups, computers, group memberships (including nested membership resolution), Service Principal Names (SPNs), Kerberos delegation configuration, and "interesting" Access Control Entries (ACEs) drawn from object security descriptors.

It is designed as a scalable, memory-bounded alternative to the PowerShell collector (`Collect-ADAuthorization.ps1`), producing output compatible with the rest of the AD-AuthGraph-v2 pipeline (`graph_builder.py`).

The tool performs **read-only** LDAP queries against Active Directory. It does not modify directory objects, ACLs, or account state. All collection is performed under the credentials of the invoking user via Windows Integrated Authentication.

## BUILD / COMPILATION

`collect-adauth` is distributed as C# source (`source/Program.cs`) and must be compiled with the .NET 8 SDK before use; no prebuilt binary is shipped.

**Prerequisites**

* .NET 8 SDK (`dotnet` on `PATH`)
* Windows, with Developer PowerShell for Visual Studio (or any shell exposing the .NET SDK)
* Microsoft Visual C++ Build Tools, per the top-level project requirements

**Steps**

1. Scaffold or open a console project targeting `net8.0` (e.g. `dotnet new console -n ADAuthCollector`), and place/replace its `Program.cs` with the collector source.
2. Restore dependencies:
   ```
   dotnet restore
   ```
3. Build a Release binary:
   ```
   dotnet build -c Release
   ```
   The build is expected to emit a series of `CA1416` platform-compatibility warnings (e.g. for `SecurityIdentifier`, `QualifiedAce.AceQualifier`, `GenericAce.IsInherited`). These flag APIs that are Windows-only; since this collector is Windows/AD-only by design, the warnings are expected and can be ignored.
4. (Recommended) Produce a standalone, distributable executable:
   ```
   dotnet publish -c Release -r win-x64 --self-contained
   ```

**Output location**

A successful build/publish produces the executable under:
```
bin\Release\net8.0\win-x64\ADAuthCollector.dll
bin\Release\net8.0\win-x64\publish\ADAuthCollector.exe   (self-contained publish output)
```
The examples in this document refer to this executable generically as `collect-adauth.exe`; rename or invoke it as produced by your build.

## AUTHENTICATION

Authentication is **Windows Integrated Authentication (Negotiate/Kerberos) only**. The tool binds to the target using `CredentialCache.DefaultNetworkCredentials` — i.e., the identity of the current process/user. There is no support for explicit username/password or alternate credentials in this build. Run the tool as a domain-joined identity that has at least read access to the objects and security descriptors you want collected.

## OPTIONS

`-h`, `/?`, `--help`
: Print usage text and exit (exit code 0).

`--host HOST`
: Domain controller hostname or DNS domain name to bind to. Falls back to `--domain` and then to the current Windows user domain if unset.

`--port PORT`
: LDAP port. Default: `389`. Must be between 1 and 65535. (Note: there is no built-in LDAPS/636 TLS option in this build — see LIMITATIONS.)

`--base-dn DN`
: Search base distinguished name. Default: the `defaultNamingContext` returned by the target's RootDSE.

`--output PATH`, `--output-path PATH`, `--output-file PATH`
: Path to the final JSON output file. Default: `ad_authorization_state.json` (resolved to an absolute path).

`--domain DOMAIN`
: Domain name recorded in output metadata. Default: the `USERDNSDOMAIN` environment variable, or derived from `--base-dn` if unset.

`--include-built-in BOOL`
: Include objects under `CN=Builtin` / `CN=Users` when enumerating groups. Default: `true`.

`--page-size N`
: LDAP paged-search page size (1–100000). Default: `1000`.

`--threads N`
: Accepted for command-line compatibility with the pipeline. **Not currently used** — LDAP writes/reads in this collector are serialized regardless of value (see LIMITATIONS).

`--verbosity {0|1|2|3}`
: Logging verbosity. `0`=quiet, `1`=summary only, `2`=summary+progress (default), `3`=debug (includes SID-resolution diagnostics).

`--resume BOOL`, `--resume-from-checkpoint BOOL`
: If `true`, sections that already have a completed checkpoint are skipped and their cached fragment reused instead of re-collected. Default: `false`.

`--checkpoint-dir DIR`
: Directory used to store per-section JSON fragments and checkpoint markers. Default: `.adcollect-checkpoints` (resolved to an absolute path).

`--checkpoint-enabled BOOL`
: Whether per-section checkpoints/fragments are written to `--checkpoint-dir` at all. If `false`, a temporary directory under the system temp path is used instead and deleted automatically at the end of the run. Default: `true`.

`--timeout SECONDS`, `--timeout-seconds SECONDS`
: Per-LDAP-operation timeout, 1–86400 seconds. Default: `30`.

`--retry-count N`, `--max-retries N`
: Number of retries for transient LDAP failures (busy/unavailable/timeout-class errors), 0–100. Default: `3`. Uses linear backoff capped at 5 seconds.

`--delay-ms N`
: Fixed delay inserted before every LDAP request, 0–600000 ms. Default: `0`. Useful for throttling collection against sensitive production DCs.

`--include-inherited-aces BOOL`
: If `true`, inherited ACEs are included in ACL output in addition to explicit ACEs. Default: `false`, matching the PowerShell collector's behavior.

Option keys are case-insensitive and accept optional `-`/`_` separators (e.g. `--basedn`, `--base_dn`, and `--base-dn` are equivalent). Values may be supplied as `--key=value` or `--key value`.

**Naming note:** the `--help` banner in the current source prints the string `collect-adauth-csharp`, while runtime error messages are prefixed `collect-adauth:`. This document uses `collect-adauth` throughout for consistency; be aware the built `--help` output itself has not been reconciled to match.

## WHAT IS COLLECTED

The collector runs, in order, the following sections, each spooled independently to disk and then assembled into the final JSON document:

1. **acl_permissions** — "interesting" ACEs (`AccessAllowed`/`AccessDenied`) from the `nTSecurityDescriptor` of user and group objects. An ACE is considered interesting if its formatted rights include `GenericAll`, `GenericWrite`, `WriteProperty`, `WriteDacl`, `WriteOwner`, a reset-password-class right, or an `ExtendedRight`. Extended rights are resolved to display names via the schema's `CN=Extended-Rights` container. Inherited ACEs are excluded unless `--include-inherited-aces` is set.
2. **groups** — sAMAccountName, SID, DN, description, member/memberOf counts, group scope (DomainLocal/Global/Universal), and group category (Security/Distribution).
3. **group_memberships** — flattened membership records including **recursively resolved nested group membership** (cycle-safe via a visited-set), with a `direct_membership` flag distinguishing direct vs. inherited-through-nesting membership.
4. **users** — sAMAccountName, SID, DN, description, enabled/disabled state, SPN count, memberOf count, and a `has_delegation` flag.
5. **delegation** — Kerberos delegation configuration for users and computers: `unconstrained` (TRUSTED_FOR_DELEGATION), `constrained_with_protocol_transition` (TRUSTED_TO_AUTH_FOR_DELEGATION), or `constrained` (via `msDS-AllowedToDelegateTo` only), including the list of allowed delegation targets.
6. **spns** — Service Principal Names registered on user and computer accounts. Default computer SPNs (`HOST/*`, `TERMSRV/*`, `RestrictedKrbHost/*`) are excluded to reduce noise.
7. **computers** — sAMAccountName, SID, DN, OS, enabled state, SPN count, and unconstrained/constrained delegation flags.

A `statistics` object (per-section record counts) and a `metadata` object (`collector_version`, `domain`, `description`, `collection_date`) are prepended to the final document.

## OUTPUT

A single JSON file at the path given by `--output`, containing top-level keys: `statistics`, `acl_permissions`, `groups`, `metadata`, `group_memberships`, `users`, `delegation`, `computers`. This structure matches the sample at `sample_output/state_5.json` and is the expected input format for `graph_builder.py`.

The file is composed by streaming each section's spooled fragment into the output rather than holding the full object graph in memory, and is written to a `.tmp` file first, then atomically moved into place — so a killed or crashed run never leaves a partially-written output file at the final path.

## CHECKPOINT / RESUME

When `--checkpoint-enabled` is `true` (the default), each completed section is written to `--checkpoint-dir` as a `<section>.array.json` fragment plus a `<section>.checkpoint.json` marker recording the section name, record count, and completion timestamp. Running again with `--resume true` causes any section with a valid checkpoint to be skipped and its cached fragment reused verbatim, rather than re-queried from AD. This allows a large collection interrupted partway through to be restarted without repeating already-completed sections. Set `--checkpoint-enabled false` to force a clean, non-resumable run using a self-cleaning temp directory.

## EXIT STATUS

`0`
: Success (including `--help`).

`1`
: Collection failed (LDAP error, I/O error, or other runtime exception). Details are printed to stderr, including a stack trace.

`2`
: Invalid command-line arguments (unknown option, missing required value, out-of-range value, unexpected positional argument).

## EXAMPLES

Collect from the current domain using defaults:
```
collect-adauth.exe
```

Collect from a specific DC, writing to a custom path, with debug logging:
```
collect-adauth.exe --host dc01.corp.example.com --output C:\collect\state.json --verbosity 3
```

Throttled collection against a sensitive production DC, including inherited ACEs:
```
collect-adauth.exe --host dc01.corp.example.com --delay-ms 50 --page-size 500 --include-inherited-aces true
```

Resume an interrupted large collection:
```
collect-adauth.exe --checkpoint-dir C:\collect\ckpt --resume true
```

## LIMITATIONS / NOTES

* `--threads` is accepted for compatibility with the pipeline's option surface but is **not implemented** — all LDAP I/O in this collector is single-threaded/serialized.
* No LDAPS (TLS) option is exposed via the CLI; `--port` alone does not enable encryption. Deploy on a trusted network path or via a signed/sealed LDAP session as governed by domain policy.
* Only user and group objects are scanned for ACLs (`CollectAcls`); computer object ACLs and OU-level ACLs are not currently collected by this build.
* Requires sufficient read rights on `nTSecurityDescriptor` (typically requires the `SACL`/`DACL_SECURITY_INFORMATION` control, which is requested automatically) and on `CN=Extended-Rights` under the configuration naming context for full extended-right name resolution.
* Run only against Active Directory environments you are authorized to assess.

## SEE ALSO

`Collect-ADAuthorization.ps1`(1), `graph_builder.py`(1), `Generate-EnterpriseAD_nodes.ps1`(1), AD-AuthGraph-v2 USER_MANUAL.md
