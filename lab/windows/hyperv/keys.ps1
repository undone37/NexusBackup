param([string]$text)
# TypeText does not reach a Linux guest's synthetic keyboard; TypeKey with virtual-key codes (US layout) does
$ns = "root\virtualization\v2"
$vm = gwmi -Namespace $ns Msvm_ComputerSystem -Filter "ElementName='nx-rct'"
$kb = @(gwmi -Namespace $ns -Query "ASSOCIATORS OF {$($vm.__PATH)} WHERE ResultClass=Msvm_Keyboard")[0]
$plain = @{ ' ' = 0x20; '-' = 0xBD; '=' = 0xBB; '/' = 0xBF; '.' = 0xBE; ';' = 0xBA }
$shifted = @{ '|' = 0xDC; '_' = 0xBD }
foreach ($c in $text.ToCharArray()) {
  $s = [string]$c
  if ($c -cmatch '[a-z]') { $vk = [int][char]$s.ToUpper(); $shift = $false }
  elseif ($c -cmatch '[A-Z]') { $vk = [int]$c; $shift = $true }
  elseif ($c -match '[0-9]') { $vk = [int]$c; $shift = $false }
  elseif ($plain.ContainsKey($s)) { $vk = $plain[$s]; $shift = $false }
  elseif ($shifted.ContainsKey($s)) { $vk = $shifted[$s]; $shift = $true }
  else { throw "no key for '$s'" }
  if ($shift) { [void]$kb.PressKey(0x10) }
  [void]$kb.TypeKey($vk)
  if ($shift) { [void]$kb.ReleaseKey(0x10) }
  Start-Sleep -Milliseconds 30
}
[void]$kb.TypeKey(13)
