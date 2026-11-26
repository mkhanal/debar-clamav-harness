# debar-clamav-harness: instructions for every coding agent

What this repository is and how its parts fit: [README.md](README.md).

## Rules

- **Debar's guidelines apply here.** Read [CODING-GUIDELINES.md](https://github.com/mkhanal/debar/blob/main/CODING-GUIDELINES.md) and [CONSTITUTION.md](https://github.com/mkhanal/debar/blob/main/CONSTITUTION.md) in the Debar repository before your first change. In short: names state intent in the domain's words; no comments except `// SAFETY:` lines and tool directives; every dependency pinned with `=`; licences permissive (MIT, BSD, ISC, Zlib, Unicode, Apache-2.0, MPL-2.0); the failing test first, named for the behaviour; no `unwrap`, `expect` or `panic!` outside tests.
- **ClamAV may be named freely here**, unlike in Debar. Its code may not be copied or translated; the observer calls libclamav's public C API only.
- **Nothing from Debar's private study folder comes here.** Notes on how ClamAV works inside stay private; this repository holds only what a user of ClamAV's public API and output can see.
- **Rust runs in Debar's toolchain image**: `./in-toolchain <command>`, pinned in `toolchain-image`. `./in-toolchain ./check` runs every check CI runs.
- **Images are pinned by digest**, and actions by commit SHA. Workflows stay zizmor-clean, with the least token permissions and no `pull_request_target`.
- **`known-differences.jsonl` only shrinks**, except when a person accepts a new difference; the commit adding it says why.

## Commits

- Sign off every commit under the Developer Certificate of Origin: `git commit -s`.
- The message says what changed and why. Code and names say what the system is now, not how it got here.
- A commit, pull request, issue or comment never credits a tool or an AI as author or co-author: no `Co-Authored-By` trailer for one, no "Generated with" line.
