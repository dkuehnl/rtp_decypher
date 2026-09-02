# RTP-Decypher

A Windows desktop tool for inspecting RTP traffic captured in `.pcap` files — browse a capture's UDP flows, parse the RTP packets within a chosen flow, and check sequence-number continuity per SSRC.

> **Status: under active development.** Core flow/SSRC/sequence analysis works, but some features are incomplete or not yet implemented (e.g. RTP payload decyphering) — see the `// TODO:` comments throughout `src/` for the current state.

---

## Why RTP-Decypher?

Diagnosing RTP issues (dropped packets, sequence gaps, SSRC rollovers) from a raw `.pcap` file usually means reaching for a full protocol analyzer just to answer a narrow question: which UDP flows in this capture are RTP, and are their sequence numbers continuous? RTP-Decypher is a focused tool for exactly that — pick a capture, pick a flow, and get per-SSRC packet counts and sequence-break/rollover detection without a general-purpose packet analyzer's overhead.

---

## Features

- **`.pcap` browsing** — a filtered file-tree view of the local filesystem, showing only `.pcap` files
- **UDP flow listing** — every distinct UDP flow (source/destination IP and port) found in the opened capture, with its packet count
- **RTP parsing per flow** — the packets of a selected flow are parsed as RTP and grouped by SSRC
- **Configurable payload offset** — an optional byte offset into each packet's UDP payload, for captures where the RTP header isn't at offset 0
- **Sequence analysis per SSRC** — expected vs. actual packet count, sequence-break detection, and rollover count

---

## Architecture

| Component | Responsibility |
|---|---|
| `MainWindow` | Top-level window; wires file browsing, flow selection, and stream analysis together |
| `PcapReader` | Opens a `.pcap` file via PcapPlusPlus and groups its UDP packets by flow |
| `RtpParser` | Parses a raw UDP payload as an RTP header (RFC 3550) |
| `StreamAnalyzer` | Parses a flow's packets as RTP, groups them by SSRC, and computes sequence-number statistics |
| `FileUtils` | Configures the file-tree view as a `.pcap`-filtered filesystem browser |

---

## Requirements

| Dependency | Notes |
|---|---|
| C++ | 17 |
| CMake | 3.16+ |
| Qt | 6, Core + Widgets modules, via MSYS2 MinGW64 |
| PcapPlusPlus | located via the `PCAPPP_ROOT` cache variable (defaults to `external/PcapPlusPlus`) |

Target platform: **Windows only** (links against `ws2_32`/`iphlpapi`).

---

## Usage

Use the file tree on the left to locate and double-click a `.pcap` file — its UDP flows are listed in the connections table. Double-click a flow to parse it as RTP; the SSRCs found in that flow appear in the stream tree, each with its endpoint and packet count. Select an SSRC and click **Analyse** (or double-click it) to see its sequence-number statistics — expected vs. actual packet count, whether a sequence break was detected, and how many rollovers occurred.

If the RTP header in your capture doesn't start at the beginning of the UDP payload, enable **Enable Payload-Offset** and set the byte offset before selecting a flow.

---

## Project Structure

```
src/
  core/        # PcapReader, RtpParser, StreamAnalyzer — business logic, no QWidget dependency
  gui/         # MainWindow, FileUtils — QWidget-based UI
tests/         # QtTest unit tests for the core/ components
```
