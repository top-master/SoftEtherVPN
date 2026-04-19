# Agent Requirements

- Agents must use LF (`\n`) line endings for new text files.
- Agents must preserve an existing text file's current line endings outside
  the lines they actually change.
- Agents must not normalize an entire existing file just to change line
  endings.
- Agents must not stage whitespace-only or EOL-only churn in untouched parts
  of a file.
- After creating a new commit, agents must run
  `sh developer_tools/fix-last-commit-whitespace.sh`.
- If the fixer changes files, agents must stage those changes and create a
  follow-up commit.
