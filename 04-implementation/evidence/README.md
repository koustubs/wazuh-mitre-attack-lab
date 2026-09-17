# Evidence

This directory contains local test output. Raw evidence is excluded from Git because it can contain account names, addresses, task contents, and installation details. Keep sanitized examples separately if they are needed for presentation.

Every live run needs its endpoint `run.json`, source records, and matching indexed alert JSON. A source event alone does not pass detection. A manager alert alone does not prove indexing. Synthetic inputs under `tests/` are rule checks only.

Use separate folders for the two required runs of each Windows and Linux scenario. The comparison run has its own folder and must not be merged into a detection run.
