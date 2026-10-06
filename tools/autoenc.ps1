param(
    [Parameter(Mandatory = $true)][string]$SrcDir,
    [Parameter(Mandatory = $true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'

$keepNames = @('TenzoRSE.h')

$skipLinePatterns = @(
    'static_assert',
    '\[\[',
    '\bextern\b',
    '\bsizeof\b',
    '\balignof\b',
    '__asm',
    '\basm\b',
    '\bchar\b\s*\w*\s*\[',
    '\b(wchar_t|char16_t|char32_t)\b',
    '\bchar\s*\*',
    '\*\s*\w+\s*=(?!=)'
)

$wrappedTailPattern = '(TENZO_OBFUSCATE|TENZO_AUTO|(?:make_obfuscated|seal)\s*<[^<>]*>)\s*\($'

function Find-StringEnd([string]$text, [int]$start) {
    $i = $start + 1
    while ($i -lt $text.Length) {
        if ($text[$i] -eq '\') { $i += 2; continue }
        if ($text[$i] -eq '"') { return $i }
        $i++
    }
    return $text.Length - 1
}

function Convert-Source([string]$text) {
    $sb = [System.Text.StringBuilder]::new()
    $i = 0
    $n = $text.Length
    while ($i -lt $n) {
        $c = $text[$i]

        if ($c -eq '#') {
            $atLineStart = $true
            for ($k = $i - 1; $k -ge 0; $k--) {
                $ch = $text[$k]
                if ($ch -eq "`n") { break }
                if ($ch -ne ' ' -and $ch -ne "`t" -and $ch -ne "`r") { $atLineStart = $false; break }
            }
            if ($atLineStart) {
                $j = $i
                while ($j -lt $n) {
                    if ($text[$j] -eq "`n" -and ($j -eq 0 -or $text[$j - 1] -ne '\')) { break }
                    $j++
                }
                if ($j -lt $n) { $j++ }
                [void]$sb.Append($text.Substring($i, $j - $i))
                $i = $j
                continue
            }
        }

        if ($c -eq '/' -and $i + 1 -lt $n -and $text[$i + 1] -eq '/') {
            $j = $text.IndexOf("`n", $i)
            if ($j -lt 0) { $j = $n }
            [void]$sb.Append($text.Substring($i, $j - $i))
            $i = $j
            continue
        }

        if ($c -eq '/' -and $i + 1 -lt $n -and $text[$i + 1] -eq '*') {
            $j = $text.IndexOf('*/', $i + 2)
            if ($j -lt 0) { $j = $n - 2 }
            [void]$sb.Append($text.Substring($i, ($j + 2) - $i))
            $i = $j + 2
            continue
        }

        if ($c -eq "'") {
            $j = $i + 1
            while ($j -lt $n) {
                if ($text[$j] -eq '\') { $j += 2; continue }
                if ($text[$j] -eq "'") { $j++; break }
                $j++
            }
            if ($j -gt $n) { $j = $n }
            [void]$sb.Append($text.Substring($i, $j - $i))
            $i = $j
            continue
        }

        if ($c -eq '"') {
            $pi = $i - 1
            $prefix = ''
            while ($pi -ge 0 -and ([char]::IsLetterOrDigit($text[$pi]) -or $text[$pi] -eq '_')) {
                $prefix = [string]$text[$pi] + $prefix
                $pi--
            }
            if ($prefix.Length -gt 0) {
                if ($prefix -eq 'R') {
                    $open = $text.IndexOf('(', $i)
                    $delim = $text.Substring($i + 1, $open - $i - 1)
                    $needle = ')' + $delim + '"'
                    $close = $text.IndexOf($needle, $open)
                    if ($close -lt 0) { $close = $n - 1 }
                    $end = [Math]::Min($close + $delim.Length + 2, $n)
                    [void]$sb.Append($text.Substring($i, $end - $i))
                    $i = $end
                }
                else {
                    $close = Find-StringEnd $text $i
                    $end = [Math]::Min($close + 1, $n)
                    [void]$sb.Append($text.Substring($i, $end - $i))
                    $i = $end
                }
                continue
            }

            $parts = @()
            $cur = $i
            $end = $i + 1
            while ($true) {
                $close = Find-StringEnd $text $cur
                $parts += $text.Substring($cur + 1, $close - ($cur + 1))
                $after = [Math]::Min($close + 1, $n)
                $k = $after
                while ($k -lt $n -and ($text[$k] -eq ' ' -or $text[$k] -eq "`t" -or $text[$k] -eq "`r" -or $text[$k] -eq "`n")) { $k++ }
                if ($k -lt $n -and $text[$k] -eq '"' -and ($k -eq 0 -or -not ([char]::IsLetterOrDigit($text[$k - 1]) -or $text[$k - 1] -eq '_'))) {
                    $cur = $k
                    continue
                }
                $end = $after
                break
            }

            $merged = [string]::Concat($parts)
            $done = $sb.ToString()
            $tail = $done.TrimEnd()
            $lineStartIdx = $done.LastIndexOf("`n") + 1
            $line = $done.Substring($lineStartIdx)

            $skip = $false
            if ($tail -cmatch $wrappedTailPattern) { $skip = $true }
            if (-not $skip) {
                foreach ($p in $skipLinePatterns) {
                    if ($line -cmatch $p) { $skip = $true; break }
                }
            }

            if ($skip) { [void]$sb.Append('"' + $merged + '"') }
            else { [void]$sb.Append('TENZO_AUTO("' + $merged + '")') }
            $i = $end
            continue
        }

        [void]$sb.Append([string]$c)
        $i++
    }
    return $sb.ToString()
}

$srcFull = [System.IO.Path]::GetFullPath($SrcDir)
$outFull = [System.IO.Path]::GetFullPath($OutDir)
if ($srcFull.TrimEnd('\') -eq $outFull.TrimEnd('\')) { exit 1 }

New-Item -ItemType Directory -Force -Path $outFull | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)

$files = Get-ChildItem -LiteralPath $srcFull -File | Where-Object { $_.Extension -in '.cpp', '.h', '.hpp' }
foreach ($f in $files) {
    $text = [System.IO.File]::ReadAllText($f.FullName)
    $converted = $text
    if ($keepNames -notcontains $f.Name) { $converted = Convert-Source $text }
    [System.IO.File]::WriteAllText((Join-Path $outFull $f.Name), $converted, $utf8)
}
