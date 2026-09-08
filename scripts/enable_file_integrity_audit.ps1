# enable_file_integrity_audit.ps1
# ============================================================================
# STEP 1 of the R-016 file-integrity correlation rollout.
# ENABLES the Windows audit plumbing that produces Security event 4663
# (Object Access / File System) consumed by winlogbeat -> ES -> apply_rules.py R-016.
#
# TWO PARTS:
#   A. auditpol: turn ON the "File System" audit subcategory (success+failure)
#   B. SACL: grant an audit ACE on each protected path for Everyone (writes)
#
# WHY: without (A) the OS doesn't emit 4663 at all; without (B) there is no
# access (what-to-track) to audit on the folders. Both are required.
#
# RUN AS ADMIN (right-click -> Run with PowerShell) in an elevated shell:
#   powershell -ExecutionPolicy Bypass -File .\enable_file_integrity_audit.ps1
#
# VERIFY afterwards:
#   auditpol /get /subcategory:"File System"
#   (Get-Acl C:\Windows\System32\drivers\etc).Sddl   # should contain (AU;;FA;;;WD)
# Then trigger a write to a protected file and confirm event 4663 arrives in
# ES within ~1-2 min (winlogbeat poll).
#
# NOTE: these paths are deliberately conservative to limit audit noise/FP.
# Add/remove paths below as desired BEFORE running.
# ============================================================================

# --- A. Enable the File System audit subcategory (globally) ---
Write-Host "==> Enabling 'File System' audit subcategory..."
auditpol /set /subcategory:"File System" /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) { Write-Error "auditpol failed (need Administrator?)"; exit 1 }

# --- B. Apply audit SACLs to protected folders ---
# The SDDL "AU" = Audit Users, GA = Generic All, WD = Everyone world.
# GRANT: (AU;;GA;;;WD) means "audit Everyone's Generic-All access" (catches WriteData).
# We also add a second ACE for delete/change via (AU;;GA;;;WD) which covers it.
$targets = @(
    "C:\Windows\System32\drivers\etc",      # hosts, networks, protocols
    "C:\Windows\System32\config",           # SAM / SECURITY / SOFTWARE hives (subkeys audit too)
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",  # persistence autostart
    "$env:USERPROFILE\.ssh",                 # SSH private keys (if present)
    "C:\inetpub"                             # webroot (if IIS/nginx local)
)

foreach ($p in $targets) {
    if (-not (Test-Path $p)) {
        Write-Host "SKIP  $p  (does not exist)"
        continue
    }
    Write-Host "==> Granting audit SACL on $p"
    $acl = Get-Acl $p
    $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "FullControl", "ContainerInherit,ObjectInherit",
        "None", "Success,Failure")
    # prevent duplicate ACE if already present
    $already = $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier])
    if (-not ($already | Where-Object { $_.FileSystemRights -eq "FullControl" })) {
        $acl.AddAuditRule($audit)
    } else {
        Write-Host "      (audit ACE already present, skipping)"
    }
    Set-Acl -Path $p -AclObject $acl
}

Write-Host ""
Write-Host "==> DONE. Verify with:"
Write-Host "    auditpol /get /subcategory:`"File System`""
Write-Host "    (Get-Acl C:\Windows\System32\drivers\etc).Sddl"
Write-Host "Then make a test write (e.g. icacls / echo>>hosts) and watch winlogbeat/ES."
