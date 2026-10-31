# Deployment Hardening

*Part of Trentina's **Security** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina holds every profile's bearer, every backend's credential, the LLM
keys and the OAuth signing key. A file-write or code-execution primitive
inside it compromises every agent it serves and lets the attacker mint OAuth
tokens. The code defends the boundary; the container has to make a bug in
that code a contained one. This page is what to run it with.
[`contrib/quadlet/trentina.container`](../contrib/quadlet/trentina.container)
is a reference unit with all of it applied.

## Containment flags

| Flag | Why |
|------|-----|
| `--read-only` (`ReadOnly=true`) | No file write can plant code. Only `/data`, a tmpfs `/tmp` and — if you want API-driven config — the config directory are writable. |
| `--security-opt no-new-privileges` | No setuid escalation from a spawned process. |
| `--cap-drop=all` | The gateway needs no capability. |
| `--user 65532` | Never root, in or out of a user namespace. |
| default seccomp profile | Never `--security-opt seccomp=unconfined`. |

The image sets `PYTHONSAFEPATH=1`, so the working directory is not on
`sys.path`, and `PYTHONDONTWRITEBYTECODE=1`. Before 0.49.0 a writable `/app`
was `sys.path[0]`, and onnxruntime and transformers are imported lazily, so a
file write there became code execution at the next import.

## A writable config directory

`config_tool` edits `profiles.yaml`, which means the gateway needs to rename a
file over it, which means the *directory* has to be writable and bound as a
directory rather than as the single file. That is a real write surface, and it
is worth being plain about what it is and is not.

It is one directory, holding config the gateway already reads. The rootfs stays
read-only, the config directory is not on `sys.path`, and nothing there is
imported, so a write cannot become code execution. `TRENTINA_REQUIRE_HARDENED`
still passes: `rootfs_writable` tests `statvfs("/")` and `import_path_writable`
tests `sys.path` entries, and a bind mount at the config path is neither.

Keep secrets out of that directory. They belong in the read-only secrets mount,
by their `_FILE` form, exactly as before — the one field in the schema that can
hold a credential value rather than the name of one is `llm_keys.*.api_key`,
and `config_tool` masks it on the way out.

If you do not want this, bind the single file `:ro` as before. `config_tool`
reads fine and reports that it cannot write, and `profiles.yaml` stays
hand-edited-only. Federation keys are unaffected either way: they live in
`/data`, not in the config directory.

## The startup check

Every network transport reads its own containment from `/proc/self` at
startup and logs one WARNING naming each gap:

| Gap | Meaning |
|-----|---------|
| `no_new_privs_off` | `no-new-privileges` is not set |
| `capabilities_held` | `CapEff` is not zero |
| `seccomp_off` | no seccomp filter |
| `rootfs_writable` | `/` is not mounted read-only |
| `cwd_on_import_path` | `PYTHONSAFEPATH` is unset |
| `import_path_writable` | a `sys.path` directory is writable by the process |
| `secret_in_environment` | a secret came in as `FOO`, not `FOO_FILE` |
| `unverifiable` | `/proc/self` could not be read, so nothing was checked |
| `l2_obfuscation_gate_failed`, `l2_obfuscation_gate_unrecorded` | the L2 model's manifest has no passing [obfuscation-gate](benchmark.md#l2-obfuscation-gate-359) record: a zero-width split or an encoding may blind it |
| `l2_benign_gate_failed`, `l2_benign_gate_unrecorded` | the L2 model's manifest has no passing [benign-gate](benchmark.md#l2-benign-gate-411-404) record at the threshold in force: it may refuse routine tool output. Setting `CLASSIFIER_THRESHOLD` to anything but the recorded threshold is this gap until the gate is run at it |

Once profiles are loaded it checks again, for every secret name configuration
read (`${VAR}` references, `llm_providers` keys, ingress tokens), because a
profile's credential in the environment is the same gap. The bridge process
runs both checks before `run`.

`TRENTINA_REQUIRE_HARDENED=true` turns any gap into a startup failure. Set it
on any deployment that serves agents you do not fully trust, which means a
coding agent or a swarm. stdio skips the check: a desktop client's child
process is not a deployment.

## Secrets

Use the `_FILE` form for every secret: `TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE`,
`TRENTINA_BACKEND_TOKEN_KEY_FILE`, `TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET_FILE`,
`GEMINI_API_KEY_FILE`,
`OPENAI_API_KEY_FILE`, `ANTHROPIC_API_KEY_FILE`, `OPENROUTER_API_KEY_FILE`,
every `${VAR}` a profile references, and the bridge's. `_FILE` wins when both
are set. A value that arrives in the environment is popped from `os.environ`
after startup (`gateway/envscrub.py`), but the kernel still serves it at
`/proc/self/environ` for the life of the process. Mount the files `0400`,
owned by the container user, read-only.

Never put a credential in a backend URL in `profiles.yaml`. Use `${VAR}` and
a header where the backend allows one.

## Network

- Publish the port on the address that needs it, not `0.0.0.0` on the host.
- Agents belong on a network with no route out (`--network` with
  `internal=true`, or `--network=none` plus the gateway's socket). Their only
  egress is the gateway.
- The gateway's own egress: `fetch` refuses non-global addresses in code
  (`egress.py`), but a host firewall is the second wall. Drop forwarded
  traffic from the gateway's address to RFC 1918, CGNAT (100.64/10),
  loopback, link-local (169.254/16, including cloud metadata) and multicast,
  and drop its input to the host except DNS. An nftables sketch:

```
table inet trentina_egress {
  chain forward {
    type filter hook forward priority -10;
    ip saddr 10.89.0.89 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
      100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 } drop
  }
  chain input {
    type filter hook input priority -10;
    ip saddr 10.89.0.89 udp dport 53 accept
    ip saddr 10.89.0.89 tcp dport 53 accept
    ip saddr 10.89.0.89 drop
  }
}
```

Pin the gateway's address (`--ip`) so the rule cannot drift. The sketch is
IPv4. If the gateway's network has IPv6, give it the same rules with
`ip6 saddr <its address>` against `::1/128`, `fc00::/7`, `fe80::/10` and
`ff00::/8`, or create the network without IPv6.
