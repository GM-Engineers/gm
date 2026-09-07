# Submitting the Tongsuo #836 comment (manual instructions)

The full comment text is ready at:
[`ISSUE-836-comment-bundled-repro-2026-09-06.md`](./ISSUE-836-comment-bundled-repro-2026-09-06.md)

It is **strictly additive** to the existing #836 — covers Path 2 and
Path 3, plus the bundled-Tongsuo self-roundtrip that rules out a
peer-client bug.

## One-step submission

1. Open: https://github.com/Tongsuo-Project/Tongsuo/issues/836
2. Scroll to the comment box at the bottom of the page.
3. Copy the **entire content** of `ISSUE-836-comment-bundled-repro-2026-09-06.md`
   (excluding the first paragraph "Comment on Tongsuo #836 …" — start
   from "## Why a comment, not a new issue").
4. Paste into the comment box, then click **Comment**.

That's it. No new issue opened, no duplicate.

## If you want to use gh CLI

```bash
# One-time setup (if not already authenticated)
gh auth login --web   # follow browser flow

# Post the comment (substitute the comment body file path)
COMMENT_FILE=/Users/laozhang/Work/opensource/gm/gm-tlcp/interop/tongsuo/upstream/ISSUE-836-comment-bundled-repro-2026-09-06.md
BODY=$(awk '/^## Why a comment, not a new issue/{found=1} found' "$COMMENT_FILE")
gh issue comment 836 --repo Tongsuo-Project/Tongsuo --body "$BODY"
```

## Verification checklist after posting

- [ ] Comment appears under #836 as a comment, not a new issue
- [ ] Comment includes the gdb-style stack for Path 2 and Path 3
- [ ] Comment includes the bundled-Tongsuo self-roundtrip snippet
- [ ] Comment references #836 as related (not duplicate)
