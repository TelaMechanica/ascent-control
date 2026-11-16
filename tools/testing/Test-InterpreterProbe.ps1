param([Parameter(Mandatory=$true)][string]$ExecutablePath)
$ErrorActionPreference='Stop'
$executable=(Get-Item -LiteralPath $ExecutablePath).FullName
$results=@()
foreach($mode in @('valid','old','invalid','stderr','stdout','hang')){
    $info=New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName=$executable
    $info.Arguments=$mode
    $info.WorkingDirectory=Split-Path -Parent $executable
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $process=New-Object System.Diagnostics.Process
    $process.StartInfo=$info
    try{
        $null=$process.Start()
        $output=$process.StandardOutput.ReadToEndAsync()
        $errors=$process.StandardError.ReadToEndAsync()
        $exited=$process.WaitForExit(9000)
        if(-not $exited){
            # taskkill is scoped to the owned harness process tree only.
            & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $process.Id /T /F *> $null
            $process.WaitForExit(3000)|Out-Null
            $results+=@{mode=$mode;passed=$false;watchdog_stopped=$true}
        }else{
            $raw=$output.GetAwaiter().GetResult()
            try{$entry=$raw|ConvertFrom-Json}catch{$entry=$null}
            $results+=@{mode=$mode;passed=($process.ExitCode -eq 0 -and $entry.passed -eq $true);milliseconds=$entry.milliseconds;watchdog_stopped=$false}
        }
    }finally{$process.Dispose()}
}
@{cases=$results;hardware_access=$false;installed_state_access=$false}|ConvertTo-Json -Depth 5
if(@($results|Where-Object{-not $_.passed}).Count){exit 1}
