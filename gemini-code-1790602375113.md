# 🛡️ Operational Runbook: OverTheWire Bandit (Stages 0 - 10)

> **Author:** Mahesh Ravindra Gummul  
> **Role:** Senior Infrastructure Engineer  
> **Target Environment:** `bandit.labs.overthewire.org` (Port 2220)  
> **Objective:** Command-line forensic extraction, system reconnaissance, and permission bypass.

---

## 🚀 I. Executive Summary

This document outlines the tactical execution and underlying Linux engineering principles for the first eleven operational stages of the OverTheWire Bandit environment. The methodologies detailed herein focus on bypassing shell interpretation anomalies, querying POSIX file system metadata, managing standard input/output streams, and utilizing core utilities for investigative data extraction. 

---

## ⚙️ II. Strategic Infrastructure Principles

Before detailing individual stage executions, the following core engineering concepts dictate the operating environment:
*   **Shell Globbing vs. C Library Parsing:** Bash interprets wildcards (`*`) and variables before passing arguments to underlying binaries. Malformed filenames (e.g., those starting with `-`) can hijack binary option parsing unless strictly defined via relative paths (`./`).
*   **File Descriptors & Stream Routing:** Standard Output (`stdout`, 1) and Standard Error (`stderr`, 2) must be actively managed during system-wide reconnaissance. Unprivileged searches require routing descriptor 2 to `/dev/null` to filter access-denial noise.
*   **Magic Numbers:** Linux does not rely on file extensions. Utilities like `file` analyze hex signatures at the byte level to determine data structures.
*   **Data Deduplication:** Unstructured data streams can be filtered by enforcing alphabetical grouping (`sort`) followed by strict adjacency comparison (`uniq`).

---

## 📊 III. Tactical Execution Matrix

| Stage | Operational Obstacle | Command Execution | Core Engineering Concept |
| :---: | :--- | :--- | :--- |
| **0 → 1** | Read standard text | `cat readme` | **Standard I/O:** Core concatenation and stream routing. |
| **1 → 2** | Bypass option parsing | `cat ./-` | **Relative Path Enforcement:** Forcing C library interpretation of `-`. |
| **2 → 3** | Handle space separators | `cat "./spaces in this filename"` | **IFS Mitigation:** Preserving argument integrity against space parsing. |
| **3 → 4** | Extract hidden files | `ls -la` then `cat .hidden` | **Dotfile Visibility:** Bypassing directory prefix hiding rules. |
| **4 → 5** | Isolate text in raw data | `file ./*` then `cat ./-file07` | **Magic Numbers:** Header byte signature inspection. |
| **5 → 6** | Local metadata search | `find . -type f -size 1033c ! -executable` | **Metadata Querying:** Precise file size and permission filtering. |
| **6 → 7** | System-wide search | `find / -user bandit7 -size 33c 2>/dev/null` | **Stream Routing:** Discarding `stderr` access-denial noise. |
| **7 → 8** | Pattern extraction | `grep "millionth" data.txt` | **String Matching:** Global Regular Expression Print stream buffering. |
| **8 → 9** | Data deduplication | `sort data.txt | uniq -u` | **Stream Piping:** Alphabetical sorting and adjacency comparison. |
| **9 → 10** | Binary string analysis | `strings data.txt | grep "==="` | **Forensic Extraction:** ASCII sequence filtering from raw binaries. |
| **10 → 11**| Decode data formats | `base64 -d data.txt` | **Encoding Translation:** Reversing safe transport transformations. |

---

## 🔍 IV. Detailed Operational Breakdown

### 🟢 Stage 0 → 1: Foundation
*   **Objective:** Extract plaintext from a standard file.
*   **Command:** 
    ```bash
    cat readme
    ```
*   **Forensic Breakdown:** The `cat` (concatenate) utility maps the file's inode, reads the data blocks sequentially, and writes the stream directly to standard output (`stdout`).

### 🟢 Stage 1 → 2: Option Parsing Bypass
*   **Objective:** Read a file named `-`.
*   **Command:** 
    ```bash
    cat ./-
    ```
*   **Forensic Breakdown:** Passing `-` directly causes `cat` to interpret it as a command-line flag or a request to read from `stdin`. Prepending the relative path identifier `./` forces the system's C library to treat the argument strictly as a file path, bypassing the option parser.

### 🟢 Stage 2 → 3: Internal Field Separator (IFS) Mitigation
*   **Objective:** Read a file with spaces: `spaces in this filename`.
*   **Command:** 
    ```bash
    cat "./spaces in this filename"
    ```
*   **Forensic Breakdown:** By default, the Bash IFS parses spaces as argument delimiters, causing `cat` to look for four separate files. Enclosing the string in quotes (or using `\` escape characters) passes the entire string as a single argument.

### 🟢 Stage 3 → 4: Dotfile Visibility
*   **Objective:** Locate and extract data from a hidden file.
*   **Commands:** 
    ```bash
    cd inhere
    ls -la
    cat .hidden
    ```
*   **Forensic Breakdown:** The Linux file system hides files purely by prefixing the filename with a period. The `-a` (all) flag overrides the `ls` utility's default behavior, exposing the hidden directory entries.

### 🟡 Stage 4 → 5: Byte-Level Signature Analysis
*   **Objective:** Identify the sole human-readable text file among raw data blobs.
*   **Commands:**
    ```bash
    cd inhere
    file ./*
    cat ./-file07
    ```
*   **Forensic Breakdown:** Bash expands `./*` into a list of all files. The `file` utility reads the magic numbers (file headers) of each. It identifies `-file07` as ASCII text based on its internal byte encoding, ignoring the lack of a file extension.

### 🟡 Stage 5 → 6: Granular Metadata Querying
*   **Objective:** Isolate a specific file based on exact byte size and permissions.
*   **Commands:**
    ```bash
    cd inhere
    find . -type f -size 1033c ! -executable
    ```
*   **Forensic Breakdown:** `find` queries the filesystem metadata directly. `-type f` filters for regular files. `-size 1033c` enforces an exact 1033-byte footprint. The logical NOT operator (`!`) combined with `-executable` evaluates the Access Control Lists (ACLs) to exclude files with the execute bit set.

### 🟠 Stage 6 → 7: System-Wide Access & Error Filtering
*   **Objective:** Search the root filesystem (`/`) for a file with specific ownership.
*   **Command:**
    ```bash
    find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
    ```
*   **Forensic Breakdown:** The utility recursively crawls from `/`, mapping files against `/etc/passwd` (UID for bandit7) and `/etc/group` (GID for bandit6). `2>/dev/null` acts as an essential stream filter, capturing all `Permission denied` errors on file descriptor 2 (`stderr`) and silently destroying them, ensuring only the valid path prints to `stdout`.

### 🟠 Stage 7 → 8: Regex and String Matching
*   **Objective:** Isolate a single line containing a specific keyword within a massive dataset.
*   **Command:**
    ```bash
    grep "millionth" data.txt
    ```
*   **Forensic Breakdown:** The Global Regular Expression Print (`grep`) utility buffers the file line-by-line, evaluating each against the target string array, and outputs only the buffered line containing the memory match.

### 🔴 Stage 8 → 9: Dataset Deduplication
*   **Objective:** Extract the only unique line from a file containing thousands of duplicates.
*   **Command:**
    ```bash
    sort data.txt | uniq -u
    ```
*   **Forensic Breakdown:** `uniq` only drops adjacent duplicates. `sort` reorganizes the raw text alphabetically, grouping all identical lines into contiguous blocks. The pipe (`|`) routes this sorted standard output into `uniq`. The `-u` flag instructs `uniq` to drop all grouped blocks and output exclusively the single line with no adjacent match.

### 🔴 Stage 9 → 10: Binary Parsing
*   **Objective:** Extract a human-readable string embedded inside a raw binary file.
*   **Command:**
    ```bash
    strings data.txt | grep "==="
    ```
*   **Forensic Breakdown:** Executing `cat` on binary data corrupts terminal character mapping. The `strings` utility safely traverses the binary, extracting only contiguous sequences of printable ASCII characters. This sanitized output is piped to `grep` to isolate the target marker.

### 🟣 Stage 10 → 11: Base64 Translation
*   **Objective:** Decode a Base64 encoded payload.
*   **Command:**
    ```bash
    base64 -d data.txt
    ```
*   **Forensic Breakdown:** Base64 is a data transport translation format, not encryption. It maps binary input into a safe 64-character ASCII alphabet to prevent corruption during transmission. The `-d` flag reverses this translation, decoding the safe ASCII back into the original plaintext data.

---

## 📌 V. Summary Takeaways

> **Key Architectural Takeaways:**
> * **The Shell vs. The Utility:** Input parsing anomalies can always be circumvented by using relative path anchors (`./`) and explicit quoting.
> * **Stream Control:** Proper routing of `stderr` (`2>/dev/null`) prevents log pollution during root-level traversals.
> * **The UNIX Philosophy:** Complex parsing is achieved by piping single-purpose tools (`cat`, `sort`, `uniq`, `grep`, `strings`) sequentially.
> * **Encoding vs. Security:** Base64 guarantees transport reliability across systems, not confidentiality.