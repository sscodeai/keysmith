# Threat model

What keysmith defends against, what it does not, and which design decisions
follow from that. Written before the redemption layer was built, so the
implementation can be checked against it.

## Adversaries

| # | Adversary | Realistic? | keysmith today | Addressed by |
|---|---|---|---|---|
| A | **Accidental leak.** The agent reads a credential and it lands in context, logs, session history, or a commit — permanently. | High. This is normal agent behaviour. | Yes: age-at-rest store, masked views, `value_file` handle passing, leak-scan + rotation | Existing core |
| B | **Injected agent.** Attacker-controlled text (repo file, issue, web page) steers the agent into exfiltrating a credential. | Medium-high in real use | **No boundary at all.** The bundled `SKILL.md` says "never `cat` a .env"; that is guidance, not access control. | Redemption layer (`keysmith run`) |
| C | **Compromised host / same-UID process.** Malware, or any process running as your user, reads `key.txt` and decrypts the store. | Out of scope | Not defended | Nothing here; use OS isolation |
| D | **Network observer.** Someone on the wire sees the credential. | Out of scope | Not defended | TLS at the destination |

Adversary B is the reason the redemption layer exists. Adversary C is
explicitly *not* a goal — a user-level process can read the store key, and
`secrets.enc` under the same UID buys nothing against it. Say so instead of
implying otherwise.

## Decisions that follow

1. **Detection-free, deterministic enforcement.** Redemption is a regex match
   plus a table lookup — no model in the enforcement path, so it is
   sub-millisecond and cannot be talked out of a decision. A probabilistic
   detector may *propose* candidates elsewhere (leak-scan), but never decides.
2. **Fail closed.** Any error in redemption (unknown session, expired session,
   name not issued in that session, missing key, malformed token, token in
   `argv`) aborts before the child process starts. There is **no fallback that
   forwards the literal placeholder**, and no fallback that sends the plaintext
   either.
3. **Session-bound tokens.** A token is only honoured if it carries a session
   id that exists, is unexpired, and had that key name issued. This is what
   stops replay of a token copied out of an old transcript or committed file.
4. **Placeholders are references, not ciphertext.** keysmith does not encrypt
   text for the model to carry (that is a different design with different
   goals — the model then cannot *use* the value). The token is a non-secret
   reference; the value never leaves the machine.
5. **Env-carried, never argv-carried.** Values are injected into the child's
   environment. A token placed in `argv` is refused, because `argv` is visible
   in `ps` to every user on the box. The actionable error message points at the
   safe pattern instead of silently doing the risky thing.
6. **Audit without secrets.** The audit log records session id, key *names*,
   the command basename and argument count — never values and never full argv
   (an argument list can itself contain a hand-inlined secret).

## Known limits (do not overstate)

- Redemption only covers processes started through `keysmith run`. Anything a
  user runs directly still sees whatever the environment gives it.
- Any process running as the same user can read the store key and every session
  file. Same-UID isolation is not provided.
- Redemption records what was used, not what was *not* used: a leaked value
  that the agent reads from a file directly is still leaked. keysmith narrows
  the path; it does not close `cat`.
- Masked views (`sk******01`) keep the first and last two characters so
  credentials stay distinguishable. That is a deliberate small disclosure — a
  mask is not a zero-information artefact.
- Nested redemption is not supported: a stored value that itself contains a
  `[[keysmith:…]]` token is never re-expanded.
