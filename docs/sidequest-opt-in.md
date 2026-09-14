# Optional Sidequest setup

**Status: staged registration; repaired-feature activation is held.** Before relying on reduced-schema auto-mode claims, custom worktree placement, or isolated integration, verify an official release contains [upstream compatibility PR #95](https://github.com/Eigenwise/eigenwise-toolshed/pull/95). An open or merged PR alone is not a published release.

## What this repository configures

`.claude/settings.json` declares the official `eigenwise-toolshed` GitHub marketplace. Claude Code adds declared marketplaces after the project folder is trusted; registration can fetch the catalog. The declaration follows the upstream default branch rather than pinning a reviewed artifact.

This change adds no `enabledPlugins`, permission rules, hook registrations, or MCP servers. Existing hooks and any enablement inherited from other settings remain unchanged. Registration is not proof that Sidequest is installed, that the repairs are available, or that workers are authorized to run.

## Operator opt-in

1. Verify the upstream release contains the required fixes and is suitable for this repository. Keep activation on hold otherwise.
2. Inspect `/plugin` for existing Sidequest installations. Do not enable competing marketplace copies blindly or replace another marketplace's identity.
3. After approval, install `sidequest@eigenwise-toolshed` in the intended scope. A machine-local project install uses `claude plugin install sidequest@eigenwise-toolshed --scope local` from this repository. This is an activating step, not part of the registration PR.
4. Reload plugins or start a new session, then verify the loaded source/version, installed identity, and supported dispatch fields. Do not use a version label alone as proof of the repairs.

## Isolated work and delivery

Create an existing, Git-ignored `.worktrees` directory through the repository's approved worktree workflow before setting Sidequest's `worktreeDirectory` to `.worktrees` and `worktreeIsolation` to `true`. The directory must be repository-relative, untracked, and free of symlink components. These board settings are local Sidequest state; this PR does not apply them.

For any separately authorized delivery, pass **both** `integrationCheckout` (the absolute path of an existing clean linked checkout of this repository) and a matching `integrationBranch` at dispatch. Do not use the shared main checkout. Omitting `integrationCheckout` retains registered-checkout integration; worktree isolation alone does not isolate delivery.

Use the actual dispatched route and hook-reported identity. Never change permission mode to make a claim pass. Existing commit, verification, review, push, and deployment gates remain in force; installing Sidequest grants no delivery or deployment authority.

Reference: [Claude Code marketplace configuration](https://code.claude.com/docs/en/plugin-marketplaces).
