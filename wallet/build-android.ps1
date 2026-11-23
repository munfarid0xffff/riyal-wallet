# Builds RiyalCoin-Wallet.apk on Windows. Run in PowerShell from the wallet\ folder:  .\build-android.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

foreach ($c in "node","npm","cargo","rustup","java","keytool") {
  if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "'$c' not found. Install Node 20+, Rust (rustup.rs) and JDK 17." }
}
if (-not $env:ANDROID_HOME) {
  $d = Join-Path $env:LOCALAPPDATA "Android\Sdk"
  if (Test-Path $d) { $env:ANDROID_HOME = $d }
}
if (-not $env:ANDROID_HOME -or -not (Test-Path $env:ANDROID_HOME)) { throw "Android SDK not found. Install Android Studio or set ANDROID_HOME." }
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME

$sdkm = Join-Path $env:ANDROID_HOME "cmdline-tools\latest\bin\sdkmanager.bat"
if (-not (Test-Path $sdkm)) { throw "Android cmdline-tools missing. Android Studio > SDK Manager > SDK Tools > 'Android SDK Command-line Tools'." }
"y`ny`ny`ny`ny`ny`ny`ny`n" | & $sdkm --licenses | Out-Null
& $sdkm "platforms;android-34" "build-tools;34.0.0" "ndk;26.1.10909125"
$env:NDK_HOME = Join-Path $env:ANDROID_HOME "ndk\26.1.10909125"

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

npm install
npm run icons
if (-not (Test-Path "src-tauri\gen\android")) { npm run tauri -- android init }
npm run tauri -- android build --apk

$bt  = Join-Path $env:ANDROID_HOME "build-tools\34.0.0"
$apk = Get-ChildItem -Recurse src-tauri\gen\android -Filter "*-release-unsigned.apk" | Select-Object -First 1
if (-not $apk) { throw "unsigned APK not found" }

$ks = Join-Path $HOME ".riyalcoin-wallet-release.jks"
$pw = Read-Host "Keystore password (min 6 chars)" -AsSecureString
$pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
if (-not (Test-Path $ks)) {
  keytool -genkeypair -keystore $ks -alias riyalcoin -keyalg RSA -keysize 2048 -validity 10000 -storepass $pass -keypass $pass -dname "CN=RiyalCoin Wallet"
}
& "$bt\zipalign.exe" -f -p 4 $apk.FullName aligned.apk
& "$bt\apksigner.bat" sign --ks $ks --ks-key-alias riyalcoin --ks-pass "pass:$pass" --out RiyalCoin-Wallet.apk aligned.apk
Remove-Item aligned.apk
& "$bt\apksigner.bat" verify RiyalCoin-Wallet.apk
Write-Host "`nDONE: $PWD\RiyalCoin-Wallet.apk - copy it to your phone and install."
