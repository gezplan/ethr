# GitHub Repository Configuration Guide

This document explains what needs to be configured on GitHub.com for the automated release workflows to work properly.

## Required GitHub Settings

### 1. Enable GitHub Actions

**Path:** Settings → Actions → General

#### Actions permissions:
- ✅ Select: **"Allow all actions and reusable workflows"**
  
  OR
  
- ✅ Select: **"Allow [your org] actions and reusable workflows"** + **"Allow actions created by GitHub"**

This allows the workflows in `.github/workflows/` to run.

---

### 2. Workflow Permissions

**Path:** Settings → Actions → General → Workflow permissions

#### Required settings:
- ✅ Select: **"Read and write permissions"**
  
  This allows workflows to:
  - Create releases
  - Upload release assets
  - Push tags (if needed)
  
- ✅ Check: **"Allow GitHub Actions to create and approve pull requests"** (optional, but recommended for future automation)

**⚠️ CRITICAL:** Without "Read and write permissions", the release workflow will fail when trying to create releases!

---

### 3. Secrets (Optional)

**Path:** Settings → Secrets and variables → Actions

The workflows use `${{ secrets.GITHUB_TOKEN }}` which is automatically provided by GitHub. You don't need to create any secrets unless you want to:

- Deploy to external services
- Trigger workflows in other repositories
- Use third-party integrations

For basic releases, **no secrets configuration is needed**.

---

## Repository Settings Checklist

Before creating your first release, verify:

- [ ] Actions are enabled (Settings → Actions → General)
- [ ] Workflow permissions set to "Read and write" (Settings → Actions → General)
- [ ] Repository is not archived
- [ ] You have push access to the repository
- [ ] Repository is either public OR you have sufficient Actions minutes (for private repos)

---

## Testing the Configuration

### 1. Push the workflow files:
```bash
cd /Users/pg/Source/ethrhub/ethr
git add .github/
git commit -m "Add GitHub Actions workflows"
git push origin master
```

### 2. Check Actions tab:
- Go to your repository on GitHub.com
- Click the "Actions" tab
- You should see the CI workflow run automatically

### 3. Create a test tag:
```bash
./release.sh 0.0.1
```

### 4. Monitor the release:
- Go to Actions tab → You should see "Build and Release" workflow running
- After completion, go to Releases tab → You should see v0.0.1 release with binaries

---

## Common Issues and Solutions

### Issue: "Resource not accessible by integration"
**Cause:** Workflow permissions are too restrictive

**Solution:** 
1. Go to Settings → Actions → General → Workflow permissions
2. Select "Read and write permissions"
3. Re-run the failed workflow

### Issue: Workflow doesn't run when tag is pushed
**Cause:** Actions might be disabled or blocked

**Solution:**
1. Check Settings → Actions → General
2. Ensure actions are allowed
3. Check if specific workflows are disabled (Actions tab → left sidebar)

### Issue: Release created but assets not uploaded
**Cause:** Artifacts weren't found or workflow permissions issue

**Solution:**
1. Check the workflow run logs for errors
2. Verify all build jobs completed successfully
3. Check artifact upload/download steps in logs

### Issue: Cannot push tags (permission denied)
**Cause:** Git authentication issue

**Solution:**
1. Ensure you're authenticated with GitHub (SSH or HTTPS)
2. Verify you have push access to the repository
3. Check if branch protection rules block tag pushes

---

## Branch Protection (Optional)

If you want to protect your main branch:

**Path:** Settings → Branches → Add branch protection rule

Recommended rules for `master`/`main`:
- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging
  - Add: "Test" (from CI workflow)
  - Add: "Lint" (from CI workflow)
- ⚠️ Do NOT enable "Include administrators" if you want to push releases directly

**Note:** Branch protection doesn't affect tag pushes, only branch pushes.

---

## Actions Minutes (Private Repositories)

For private repositories, be aware of Actions usage limits:

| Plan | Actions minutes/month |
|------|---------------------|
| Free | 2,000 minutes |
| Pro | 3,000 minutes |
| Team | 10,000 minutes |
| Enterprise | 50,000 minutes |

**Public repositories:** Unlimited minutes ✨

Each release build uses approximately 10-15 minutes (building 5 platforms).

---

## Security Considerations

### Workflow security:
- Workflows run in isolated environments
- Each workflow has its own `GITHUB_TOKEN` with limited permissions
- Workflows can only access your repository by default
- Secrets are never exposed in logs

### Release security:
- Only users with push access can create tags
- Only tags trigger release builds
- All builds are reproducible and logged
- Source code is always attached to releases

---

## Monitoring and Notifications

### Email notifications:
By default, you'll receive emails for:
- Failed workflow runs
- First successful run after a failure

### Disable notifications:
**Path:** Settings → Notifications → Actions

Or add to your workflow file:
```yaml
notifications:
  email: false
```

### Slack/Discord integration:
Add webhook secrets and steps to your workflow to send notifications to team chat.

---

## Next Steps After Configuration

1. ✅ Verify settings (use checklist above)
2. 🚀 Push workflow files to GitHub
3. 🧪 Create a test release (v0.0.1)
4. 📊 Monitor in Actions tab
5. ✨ Celebrate your first automated release!

---

## Support

If you encounter issues:

1. Check the workflow run logs (Actions tab → failed run → click on jobs)
2. Verify all settings match this guide
3. Search GitHub's documentation: https://docs.github.com/en/actions
4. Check GitHub Actions community: https://github.community/c/actions

---

## Reference Links

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication)
- [Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [Release Actions](https://github.com/softprops/action-gh-release)
