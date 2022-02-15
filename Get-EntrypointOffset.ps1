Param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Path = ""
)

$offset = (Get-Content -Path $Path  | sls " _code ").Line.substring(6,8)
 Write-Host "_code entry point offset: $offset"