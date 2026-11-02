# Host side of the mssql plugin on Windows (plugins/mssql/README.md): uploaded into the staging folder by every run
# and started as `powershell -File nexus-sql.ps1 <server>` with a T-SQL batch on stdin. Runs it with integrated
# security (the SSH account) and prints every row as one line, fields separated by tabs. Errors: stderr, exit 1.
param([string]$Server)
$ErrorActionPreference = 'Stop'
$sql = [Console]::In.ReadToEnd()
$c = New-Object System.Data.SqlClient.SqlConnection "Server=$Server;Database=master;Integrated Security=SSPI;TrustServerCertificate=true;Connect Timeout=30;Application Name=nexusbackup"
try {
	$c.Open()
	$k = $c.CreateCommand(); $k.CommandText = $sql; $k.CommandTimeout = 0
	$r = $k.ExecuteReader()
	do {
		while ($r.Read()) {
			$f = for ($i = 0; $i -lt $r.FieldCount; $i++) { if ($r.IsDBNull($i)) { 'NULL' } else { [string]$r.GetValue($i) } }
			[Console]::Out.WriteLine(($f -join "`t"))
		}
	} while ($r.NextResult())
	$r.Close()
} catch {
	[Console]::Error.WriteLine($_.Exception.Message)
	exit 1
} finally { $c.Close() }
