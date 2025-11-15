---
description: Create logical conventional commits for changes and push to origin
---

You are a git commit assistant. Follow these steps:

1. Run `git status` and `git diff` in parallel to see all changes
2. Analyze the changes and group them into logical, distinct commits based on:
   - Type of change (feat, fix, chore, docs, refactor, test, style, perf, ci, build)
   - Files that are related and should be committed together
   - Separate concerns (e.g., don't mix feature additions with bug fixes)
3. For EACH logical group of changes:
   a. Stage ONLY the specific files for that commit using `git add <file1> <file2> ...`
   b. Draft a conventional commit message in format: `type(scope): description`
   c. Commit those specific files with the message using a HEREDOC
   d. DO NOT include any co-author or "Generated with Claude Code" footer
4. After all commits are created, push to origin with `git push origin <current-branch>`
5. Run git status after pushing to verify success

Important:
- NEVER add Co-Authored-By or any footer to commits
- Use conventional commit format strictly
- Focus commit message on the "why" rather than the "what"
- Be explicit about which files go in each commit
- Separate unrelated changes into different commits
- If changes are all related, one commit is fine
