# debar-clamav-harness

The comparison harness for [Debar](https://github.com/mkhanal/debar) and the ClamAV signature format. It scans the same files with ClamAV 1.5.4, the reference scanner the ClamAV databases were written for, and with Debar, lines up what each one reached inside every file and what each one detected, object by object, and names every difference. A committed list of known differences lets it run on every Debar change while most of Debar is still to be built: a run fails only on a difference not on the list.

## The parts

| Path | What it is |
| --- | --- |
| `observer/` | The reference observer: a C program linked to libclamav 1.5.4 through its public API, and the image it runs in |
| `observer-image` | The observer image the harness runs, pinned by digest |
| `schema/` | The report schema (`report.schema.json`) and the `harness-report` crate that reads and writes it |
| `harness/` | The `harness` command: `compare` two reports, or `run` both scanners over inputs and compare |
| `builder/` | The input builder: turns each pattern signature into a file it must match, and proves those files against the reference scanner |
| `stand-in/` | `debar-stand-in`, which writes a valid report of the top-level object alone, to prove the Debar side until Debar can scan |
| `known-differences.jsonl` | The ratchet for the stand-in: every difference already known |
| `debar-known-differences.jsonl` | The ratchet for Debar, which Debar's CI judges its fixtures and its inputs built for targets 0 and 4 by |
| `debar-known-differences-web-pages.jsonl`, `debar-known-differences-text.jsonl` | Debar's ratchets for inputs built for targets 3 and 7, whose detections come only from normalised content Debar does not build yet |
| `fixtures/build` | Builds the small fixture files CI compares: the EICAR test file, a zip holding it beside a clean file, a clean text file and a file too small to scan |
| `builder/build-inputs.sh` | Unpacks the pinned databases and builds a sample of inputs with the builder |
| `builder/prove-against-reference.sh` | Proves built inputs against the reference scanner |
| `.github/workflows/compare.yml` | The reusable workflow Debar's CI calls |

## Running it locally

Everything runs in containers; Docker is the only requirement. On macOS a Linux virtual machine such as OrbStack or Docker Desktop provides it.

```sh
fixtures/build target/fixtures
./run-harness run \
  --input target/fixtures \
  --debar-command 'debar-stand-in --databases "$HARNESS_DATABASES" "$HARNESS_INPUT" "$HARNESS_REPORT"' \
  --known-differences known-differences.jsonl
```

`./run-harness` builds the workspace in Debar's toolchain image (`./in-toolchain`, pinned in `toolchain-image`), then runs `target/release/harness` in a small Debian container that can reach the host's Docker, with this repository and the current directory mounted at their own paths. Inputs, the work directory and anything the Debar command touches must lie under one of those two. The work directory defaults to `target/tmp/debar-clamav-harness`; it keeps the databases, both reports of every input and nothing else, so a difference can be inspected after the run.

`./in-toolchain ./check` runs every check CI runs: formatting, clippy, tests, cargo-deny and zizmor.

### `harness run`

```text
harness run --input FILE_OR_DIRECTORY --debar-command COMMAND
            [--known-differences FILE] [--observer-image IMAGE] [--work-directory DIRECTORY]
            [--manifest FILE]
```

1. Every regular file under the input is an input, in name order.
2. The databases are copied out of the observer image, so both scanners load the same files.
3. The observer scans every input in one container, with no network.
4. `COMMAND` runs under `sh -c` once per input, with `HARNESS_INPUT` (the file to scan), `HARNESS_REPORT` (where to write its report) and `HARNESS_DATABASES` (the directory of databases) set. It must write a report in the schema below and exit 0; any other exit stops the run.
5. Each pair of reports is compared, and the differences are judged against the known differences.
6. With `--manifest`, the builder's `manifest.tsv` for the inputs, the run also counts how many inputs each scanner detected under the signature the input was built for.

### `harness compare`

```text
harness compare --reference REPORT --debar REPORT [--known-differences FILE]
```

Compares two reports already written.

Both commands print the new differences, the known ones and the known ones that no longer occur, each with the line that names it in the known differences. They exit 0 when every difference is known, 1 when a new difference was found, and 2 when the comparison could not be made.

## The report schema

A report describes one scanned input in [JSON Lines](https://jsonlines.org/): one record per object, the top-level object first and every other object after its parent. [`schema/report.schema.json`](schema/report.schema.json) is the JSON Schema of one record. Schema version 1:

| Field | Meaning |
| --- | --- |
| `schema` | `1` |
| `id` | The object's identifier, unique within the report |
| `parent` | The parent's `id`; `null` for the top-level object only |
| `depth` | How deep the scanner was when it reached the object; the top level is 0, and a child is deeper than its parent |
| `type` | The file type the scanner settled on, by ClamAV's type names such as `CL_TYPE_ZIP`; `null` when it was not typed |
| `size` | The object's length in bytes |
| `sha256` | The SHA-256 of the object's bytes, lowercase hexadecimal |
| `detections` | Each signature name reported on the object, once per report, in order |
| `verdict` | Top-level only: `nothing_found`, `trusted`, `strong_indicator` or `potentially_unwanted` |
| `scanner` | Top-level only: `name`, `version`, and `databases`, each with its `name` (file name without extension) and the `version` in its header, sorted by name |

```json
{"schema":1,"id":0,"parent":null,"depth":0,"type":"CL_TYPE_ZIP","size":314,"sha256":"fe27bd4c…","detections":[],"verdict":"strong_indicator","scanner":{"name":"ClamAV","version":"1.5.4","databases":[{"name":"bytecode","version":339},{"name":"daily","version":28165},{"name":"main","version":63}]}}
{"schema":1,"id":1,"parent":0,"depth":1,"type":"CL_TYPE_TEXT_ASCII","size":68,"sha256":"275a021b…","detections":["Eicar-Test-Signature","Eicar-Test-Signature","Eicar-Signature"]}
```

The `harness-report` crate reads a report into a type that can only hold a valid one: one top-level object first, unique ids, every parent recorded before its children, every child deeper than its parent, hashes of 64 lowercase hex digits, no unknown fields. Debar writes its reports with the same crate or to the same schema.

## What the observer records

The observer loads every database in the pinned image's `/var/lib/clamav` (`main`, `daily` and `bytecode`) as `clamscan` does by default, and scans each input with `clamscan`'s default options plus `--allmatch`: every parser on, heuristic alerts on, the library's default limits, the clean cache on. It registers three of libclamav's scan callbacks:

- **`CL_SCAN_CALLBACK_FILE_TYPE`** records an object the first time it is typed: its id, its nearest recorded ancestor as parent, its depth, size and SHA-256. Each later call updates its type. This callback also fires for objects answered from the clean cache, which never reach the others.
- **`CL_SCAN_CALLBACK_POST_SCAN`** records the type the object finally settled on.
- **`CL_SCAN_CALLBACK_ALERT`** attributes each detection to the object it was raised on, taking the exact name from the virus-found callback that libclamav calls just before it, and accepts the alert.

So an object, in the reference's reports, is something libclamav typed. Content it pattern-matches without typing, such as the normalised views of an HTML file, is not an object; a detection raised on such a view is attributed to the nearest object above it. A file of 5 bytes or less is never typed: the top-level record of such an input has `"type": null`, with its size and hash measured by the observer.

**Observer limit.** With all-match on, libclamav reports potentially unwanted detections (names starting `PUA.`, `Heuristics.` or `BC.Heuristics.`) after the whole scan, without the object they were raised on. The observer attributes each one to the deepest object whose last alert it was when that object finished scanning, and otherwise to the top-level object. A wrongly attributed one appears as a detection on one object in the reference and on another in Debar.

## Matching objects and naming differences

The two reports are walked together from the top-level objects, which must have the same SHA-256 or the reports are of different inputs. Under each pair of matched objects, their children are paired:

1. **Same content.** Each reference child, in the order the reference reached it, pairs with the first unpaired Debar child with the same SHA-256. Identical siblings pair one for one, so a duplicate one scanner reached and the other did not is reported once.
2. **Same type.** Each reference child still unpaired pairs with the first unpaired Debar child of the same type: the same object, extracted differently.
3. **Unpaired.** What remains is an object only one side reached, reported with everything under it.

The order in which either side reached its children never matters, only their content and then their type. Every object is named by its **path**: the SHA-256 of each object from the top-level object's child down to it, by the reference's content wherever both sides were paired. The top-level object's path is empty, and the input is named by its own SHA-256.

| Kind | When |
| --- | --- |
| `databases_differ` | The two scanners loaded different database versions |
| `verdict_differs` | The verdicts for the whole input differ |
| `object_only_in_reference`, `object_only_in_debar` | An object one side reached and the other did not, with its type and detections |
| `type_differs` | A paired object was typed differently |
| `depth_differs` | A paired object was reached at another depth |
| `size_differs` | A paired object's length differs |
| `hash_differs` | A paired object's content differs at the same length |
| `detection_only_in_reference`, `detection_only_in_debar` | A signature one side reported on a paired object and the other never did, once per report |
| `detection_count_differs` | A signature both sides reported on a paired object, a different number of times, with both counts |

## The ratchet

`known-differences.jsonl` holds one difference per line, in exactly the JSON the harness prints under each difference:

```json
{"input":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","kind":"detection_only_in_reference","path":[],"signature":"Eicar-Signature"}
```

- A difference on the list is known and does not fail the run. A line naming an input covers one occurrence, and must match the difference exactly.
- A line naming no input is a rule: it covers every difference, on any input and any number of times, whose fields include all of the rule's fields. `{"kind":"type_differs","debar":null}` covers every object Debar did not type. A rule that covered nothing in a run is reported, without failing it.
- A line may say in a `gap` field which missing piece of the scanner under test it stands for, as a sentence. The field is the line's explanation and is never matched against a difference.
- A difference not on the list is new and fails the run.
- A line for an input that was compared, matching no difference, no longer occurs: the run reports it so the line can be removed. It does not fail the run, so a Debar change that closes a gap is not blocked on this repository.

The list only shrinks as Debar's pieces land. A line is added only when a person accepts the difference, in a commit that says why.

`known-differences.jsonl` holds what the stand-in cannot do: it types nothing, extracts nothing and detects nothing. `debar-known-differences.jsonl` holds what Debar does not yet do, which shrinks as its pieces land.

## The input builder

`builder/` (crate `clamav-input-builder`, command `builder`) turns pattern signatures into inputs that must match them, so every signature Debar is meant to detect can be checked with a file built from the signature itself. It is proved against the reference scanner before it judges Debar: an input the reference does not detect is a failure of the builder.

```text
builder survey --database-dir DIR [--details FILE]     account for every signature: built, or why not
builder build --database FILE --signature NAME --out FILE
builder sample --database-dir DIR --out-dir DIR [--extended N] [--logical N] [--seed N]
               [--target N] [--boundary N]
builder check --manifest FILE --scan-output FILE [--failures FILE]
```

Of the 3,641,493 signatures in the pinned `main` and `daily` databases, **42,530 are built**. The rest are not built, each for a named reason the survey counts:

| Not built because | Signatures |
| --- | --- |
| A hash signature, checked by lookup instead | 3,212,887 |
| Needs a PE container around it | 369,986 |
| Needs another container (OLE2, ELF, Mach-O, PDF, Flash, graphics, Java, archive metadata) | 13,078 |
| Needs a `Container:` or `Intermediates:` condition | 2,177 |
| Needs a regular-expression, byte-comparison or image fuzzy hash subsignature | 348 |
| Other reasons: normalised content, functionality level, ignore lists, conflicting offsets, unreadable | 487 |

`builder sample --target N` draws only signatures of target type `N`. `--boundary N` also writes, for the first `N` drawn extended signatures placed anywhere, three inputs that put the built bytes across the file's first 128 KiB boundary, a quarter, half and three quarters of the way in (`b00000-0.bin` and on, in the same manifest).

`builder/build-inputs.sh WORK_DIRECTORY` unpacks `main` and `daily` and builds a sample into `WORK_DIRECTORY/sample`, set by `EXTENDED_SAMPLE`, `LOGICAL_SAMPLE`, `SAMPLE_SEED`, `SAMPLE_TARGET` and `BOUNDARY_SAMPLE`.

`builder/prove-against-reference.sh WORK_DIRECTORY` unpacks `main` and `daily` from the pinned ClamAV image with `sigtool`, builds a sample of inputs in the toolchain image, scans them with that image's `clamscan --allmatch --no-summary --disable-cache`, and fails on any input not detected by the signature it was built for. `EXTENDED_SAMPLE`, `LOGICAL_SAMPLE` and `SAMPLE_SEED` set the sample; the sample is drawn by a small seeded shuffle of the builder's own, so the same seed draws the same signatures whatever crate versions change. The `Builder proof` workflow proves the seed-1 sample (2,500 inputs) on every change and every buildable signature weekly.

The proof reads `clamscan`'s output rather than the observer's reports: it needs only which signatures matched each file, from the same library and databases, and scans with the clean cache off so that identical inputs cannot hide one another.

## Using it from Debar's CI

Debar's CI calls the reusable workflow, pinned to a commit of this repository:

```yaml
jobs:
  compare:
    permissions:
      contents: read
    uses: mkhanal/debar-clamav-harness/.github/workflows/compare.yml@<commit>
    with:
      harness-ref: <the same commit>
      build-command: ./in-toolchain cargo build --release --locked
      debar-command: debar/target/release/debar <arguments that scan "$HARNESS_INPUT" with the databases in "$HARNESS_DATABASES" and write the report to "$HARNESS_REPORT">
```

With `built-target: "0"` it scans, instead of the fixtures, an input built from every buildable extended signature of that target type plus `boundary-sample` (default 2,000) signatures across a 128 KiB boundary, and reports how many each scanner detected under the signature each input was built for. `known-differences` names the ratchet file to judge by (default `known-differences.jsonl`); Debar passes `debar-known-differences.jsonl`, or for targets 3 and 7 the ratchet named for that target's content.

It runs on amd64 and arm64. It checks out this repository at `harness-ref` into `harness/` and Debar (by default the calling repository at the triggering commit; `debar-repository` and `debar-ref` override them) into `debar/`, runs `build-command` inside `debar/`, builds the fixtures unless `inputs-directory` names others, and runs `harness/run-harness run` from the directory holding both checkouts with this repository's known differences. This repository's own CI calls the same workflow with the stand-in as Debar.

## The observer image

`observer/Dockerfile` builds the observer in the pinned `clamav/clamav-debian:1.5.4` image (`sha256:cce3e1a4…`), so the library under observation and the databases are byte for byte those of that image. The image ships no C headers, so the build takes the public headers from the ClamAV 1.5.4 source tarball, checking its SHA-256 (`1af1117a…`), and configures the two generated ones itself. The observer is compiled against them and linked to the image's own `libclamav.so.12`. Databases are never downloaded from ClamAV's servers.

The `Observer image` workflow builds the image natively on amd64 and arm64 whenever `observer/` changes on `main`, checks that each detects the EICAR test file, publishes one multi-architecture image to `ghcr.io/mkhanal/debar-clamav-observer`, and prints its digest. Committing that digest to `observer-image` is what moves the harness to the new observer; the `harness` binary carries the pinned image from the commit it was built at.

## Licences

This repository's sources are under the Mozilla Public License 2.0 ([LICENSE](LICENSE)).

The observer links libclamav, which is under the GNU General Public License version 2. A distributed observer binary, and the observer image, which also carries ClamAV itself and its databases, are therefore under GPL-2.0, with the observer's corresponding source in `observer/` and ClamAV's in the source tarball named above. The databases are under their publisher's terms.

## Contributing

Commits are signed off under the [Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`). See [AGENTS.md](AGENTS.md).
