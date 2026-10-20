# Prints one line per entry under $args[0] (relative path, type, attributes, times, owner + DACL, streams,
# link target, SHA256) for comparing an original tree with its restore (lab/windows/e2e.sh restore).
param([string]$Root)
$root = (Resolve-Path -LiteralPath $Root).ProviderPath.TrimEnd('\')
$keep = 'ReadOnly,Hidden,System,Archive,NotContentIndexed,ReparsePoint,Directory'
# Windows PowerShell 5.1 descends into directory junctions and symlinks; their targets are restored verbatim
# (outside the restore tree), so only the link itself is listed, not what it points to
$skip = @()
Get-ChildItem -LiteralPath $root -Recurse -Force -Attributes !Offline | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($root.Length)
    if ($skip | Where-Object { $rel.StartsWith($_ + '\') }) { return }
    if ($_.PSIsContainer -and $_.LinkType) { $skip += $rel }
    $attr = ($_.Attributes -band [IO.FileAttributes]$keep).ToString()
    $acl = Get-Acl -LiteralPath $_.FullName
    # inherited ACEs come from the parent, which differs between original and restore target
    $explicit = ($acl.Access | Where-Object { -not $_.IsInherited } |
        ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights):$($_.AccessControlType)" }) -join ';'
    $streams = ''
    $hash = ''
    if (-not $_.PSIsContainer -and -not $_.LinkType) {
        $streams = (Get-Item -LiteralPath $_.FullName -Force -Stream * | Where-Object Stream -ne ':$DATA' |
            ForEach-Object { "$($_.Stream)=$($_.Length)" }) -join ','
        $hash = (Get-FileHash -LiteralPath $_.FullName).Hash
    }
    # hard link partners are paths inside the tree; symlink/junction targets are restored verbatim
    $link = if ($_.LinkType -eq 'HardLink') { 'HardLink>' + (($_.Target | ForEach-Object { $_.Replace($root, '<root>') }) -join ',') } else { "$($_.LinkType)>$($_.Target)" }
    $prot = if ($acl.AreAccessRulesProtected) { 'protected' } else { 'inherits' }
    "$rel|$attr|$($_.LastWriteTimeUtc.ToString('o'))|$($_.CreationTimeUtc.ToString('o'))|$($acl.Owner)|$prot|$explicit|$streams|$link|$hash"
}
