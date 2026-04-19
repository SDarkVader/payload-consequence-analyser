# payload-consequence-analyser
Check AI Payload Before Merge Analyser
# Payload Consequence Analyzer 
## What This Is 
A tool that tells you what actually happens if you merge a branch — 
before you merge it. 
## The Incident That Built This 
On April 18, 2026, OpenAI's Codex surfaced a pull request on my 
AIntegrity repository described as a "minor syntax fix." 
The branch was 10 months old. If merged: - 60 files deleted - 11,967 lines of code removed - 217 passing tests destroyed - 98.7% of the working codebase gone 
Nothing in the Codex review surface communicated this. 
See FORENSIC_REPORT.md for the full analysis. 
## What It Does 
Before you merge any AI-generated PR, this tool answers: 
1. How many files are deleted vs added? 
2. How old is the branch vs current main? 
3. Do the deletions destroy tests, APIs, or core architecture? 
4. Does the PR description match what the diff actually does?
