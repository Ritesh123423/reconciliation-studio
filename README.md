# Reconciliation Studio

A single-file, 100% browser-based tool for bank-vs-books reconciliation and bank statement analysis. Nothing you upload ever leaves your browser — there is no server-side processing or storage.

## Features

- **Bank vs books reconciliation**: upload bank statements and your bank book (Excel/CSV), and the tool matches them line by line — exact matches, reversals, batch payments, part payments, and more — with every match explained.
- **Bank statement analysis**: upload bank statements (PDF, scanned image, or the bank's own Excel export) for one client or many. Every line is read and proved against the running balance, then the tool finds inter-bank transfers and reversals and prepares a full analysis (summary, monthly figures, categorisation, Excel export).
- Scanned PDFs are read with an embedded, offline OCR engine (no internet connection needed, nothing uploaded anywhere).

## Running it

Just open `index.html` in a browser — no build step, no server, no installation. Or visit the hosted version if one is linked from this repository.

## Privacy

This tool runs entirely client-side. Files you upload are processed and stored only in your own browser's local storage (IndexedDB) and are never transmitted anywhere.
