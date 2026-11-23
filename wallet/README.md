# محفظة RiyalCoin (Android · Windows · Linux · macOS)

محفظة بواجهة واحدة (Tauri 2) تشغّل **عقدة RiyalCoin الكاملة داخل التطبيق** (نفس شيفرة Rust في `../src`)
وتتحدث معها عبر RPC المحلي (127.0.0.1 + cookie). الواجهة عربية/إنجليزية (RTL) في `ui/`.

الميزات: الرصيد، الاستلام (عنوان جديد + نسخ)، الإرسال مع شاشة تأكيد، السجل، تشفير المحفظة (Argon2id)،
قفل/فتح، نسخة احتياطية، اختيار الشبكة وعقد البذور.
الاستلام يعرض رمز QR؛ الإرسال يدعم مسح QR بالكاميرا (Android فقط، عبر الإضافة الرسمية barcode-scanner)؛ الإعدادات تدعم الاستعادة من نص النسخة الاحتياطية. غير موجود: التعدين، مسح الكاميرا على سطح المكتب.

## البناء الآلي (الطريقة الموصى بها)
1. ارفع مجلد `riyalcoin` كاملًا إلى مستودع GitHub.
2. تبويب Actions ← **Build RiyalCoin Wallet** ← Run workflow (أو ادفع وسم `v0.1.0`).
3. من نتائج التشغيل (Artifacts) نزّل:
   - Linux: `.deb` و`.AppImage`   - Windows: `.msi` و`-setup.exe`
   - macOS: `.dmg` (Intel + Apple Silicon)   - Android: `RiyalCoin-Wallet.apk`

لتوقيع APK بمفتاح ثابت (ضروري للتحديثات) أضف أسرار المستودع:
`ANDROID_KEYSTORE_B64` (ملف jks بصيغة base64) و`ANDROID_KEYSTORE_PASS` و`ANDROID_KEY_ALIAS`.
بدونها يُوقَّع بمفتاح مؤقت ولا يمكن تحديث التطبيق فوق نسخة سابقة.
macOS/Windows غير موقّعين: سيظهر تحذير SmartScreen/Gatekeeper حتى تضيف شهادات توقيع.

## بناء APK على جهازك بدون GitHub
المتطلبات مرة واحدة: Node 20+، Rust (rustup.rs)، JDK 17، وAndroid Studio (يثبّت Android SDK؛ ومن SDK Manager فعّل
"Android SDK Command-line Tools"). ثم من مجلد `wallet`:

    ./build-android.sh        # Linux / macOS
    .\build-android.ps1       # Windows (PowerShell)

الناتج `RiyalCoin-Wallet.apk` في المجلد نفسه. أول بناء يستغرق وقتًا (تنزيل NDK وتجميع Rust). يُنشأ مفتاح التوقيع مرة واحدة في
`~/.riyalcoin-wallet-release.jks` (احفظه وكلمة مروره: التحديثات المستقبلية تحتاج المفتاح نفسه).

## البناء المحلي
المتطلبات: Rust، Node 20+، ومتطلبات Tauri للمنصة (https://tauri.app/start/prerequisites/).

    cd wallet
    npm install
    npm run icons          # يولّد الأيقونات من src-tauri/app-icon.png
    npm run tauri dev      # تشغيل للتجربة
    npm run tauri build    # حزم سطح المكتب

Android (يتطلب Android SDK/NDK وJDK 17):

    npm run tauri android init
    npm run tauri android build --apk

## ملاحظات مهمة
- لا توجد عقد بذور مدمجة: بدون عقدة بذور منشورة لن تتزامن المحفظة (الإعدادات ← عقد البذور).
- الشبكة الرئيسية لا تقبل كتلًا قبل 2026-12-31 22:00 UTC (قاعدة الإطلاق في البروتوكول).
- البرنامج **غير مُدقَّق أمنيًا** (انظر README الرئيسي). لا تضع فيه أموالًا حقيقية قبل مراجعة مستقلة.
- النسخة الاحتياطية تُعرض كنص (hex) تحفظه خارج الجهاز، وتُستعاد بلصقه في الإعدادات ← استعادة المحفظة (المحفظة القديمة تُحفظ باسم wallet.dat.bak-… ولا تُحذف).
- العقدة تعمل فقط والتطبيق مفتوح (خصوصًا على الهاتف)، وتتزامن عند كل فتح.
- لم يُجرَّب تجميع Rust/Tauri وبناء APK في بيئة الإنشاء (بلا إنترنت)؛ شغّل سير العمل وأرسل لي أي خطأ لأصلحه.
