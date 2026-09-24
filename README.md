# TUNNEL-MANAGER

پنلِ کنترلِ فلیت. یک سرویسِ پایتون روی سرورِ مرکزی، با رابطِ کاربریِ React.

> `<TOKEN>` در همهٔ دستورهای زیر = یک GitHub PAT با دسترسیِ **Contents: Read**
> (این ریپو خصوصی است). آن را یک‌بار در خطِ اولِ هر بلوک بگذار.

## نصب

روی سرورِ مرکزی — Debian/Ubuntu با systemd، به‌عنوان root. کلِ بلوک را یک‌جا کپی کن:

```bash
TOKEN=<TOKEN>
REPO=https://api.github.com/repos/Angize/TUNNEL-MANAGER
ASSET=$(curl -fsSL -H "Authorization: token $TOKEN" "$REPO/releases/latest" \
  | python3 -c "import json,sys;print([a['url'] for a in json.load(sys.stdin)['assets'] if a['name'].endswith('.tar.gz')][0])")
curl -fsSL -H "Authorization: token $TOKEN" -H "Accept: application/octet-stream" "$ASSET" -o /tmp/tnl.tgz
rm -rf /tmp/tnl && mkdir -p /tmp/tnl && tar xzf /tmp/tnl.tgz -C /tmp/tnl
cd /tmp/tnl && sudo python3 tnl-central.py --install
```

نصب‌کننده هفت مرحله را نشان می‌دهد: پیش‌نیازها (`openssl`, `ca-certificates`, `iproute2`,
`openssh-client`, `sshpass`, `redis-server`, `python3-redis`)، ذخیره‌سازِ ردیس، فایل‌ها،
پورت و نام‌کاربری/رمز، کلیدِ امضا، سرویسِ systemd، و دانلودِ هستهٔ `latest` و ایجنتِ نود.
آخرش نشانیِ پنل را چاپ می‌کند.

اگر وسطِ کار Ctrl+C بزنی، هیچ‌چیز نصفه نمی‌ماند — پیغامِ لغو می‌دهد و برمی‌گردد.

## بروزرسانی

همین یک بلوک، کامل:

```bash
TOKEN=<TOKEN>
REPO=https://api.github.com/repos/Angize/TUNNEL-MANAGER
ASSET=$(curl -fsSL -H "Authorization: token $TOKEN" "$REPO/releases/latest" \
  | python3 -c "import json,sys;print([a['url'] for a in json.load(sys.stdin)['assets'] if a['name'].endswith('.tar.gz')][0])")
curl -fsSL -H "Authorization: token $TOKEN" -H "Accept: application/octet-stream" "$ASSET" -o /tmp/tnl.tgz
rm -rf /tmp/tnl && mkdir -p /tmp/tnl && tar xzf /tmp/tnl.tgz -C /tmp/tnl
cd /tmp/tnl
sudo install -m755 tnl-central.py /opt/tnl-central/tnl-central.py
sudo python3 tnl-central.py --install-ui
sudo systemctl restart tnl-central
```

اگر فقط رابطِ کاربری عوض شده، `--install-ui` به‌تنهایی کافی است و ری‌استارت لازم
نیست — فایل‌ها از روی دیسک سرو می‌شوند. نامِ فایل‌های `ui/assets/` هش‌دار است، پس
مرورگر نسخهٔ تازه را می‌گیرد و کهنه را از کش نمی‌خواند.

> دستورِ قدیمی که فقط `tnl-central.py` را می‌گرفت دیگر کار نمی‌کند. رابطِ کاربری
> یک بیلدِ جداست که گیت‌هاب روی هر تگِ `v*` می‌سازد (ورک‌فلوی `release-panel`) و باید
> در `/opt/tnl-central/ui` بنشیند؛ به همین دلیل نصب و آپدیت از **ریلیز** است نه از
> فایلِ خامِ `main`.

## منویِ روت

```bash
sudo python3 /opt/tnl-central/tnl-central.py
```

بالای منو وضعیتِ زنده را می‌بینی: سرویس، نشانیِ پنل، نام‌کاربری، تعدادِ فایل‌های
رابطِ کاربری، و تعدادِ نود و لینک. گزینه‌ها:

| | |
|---|---|
| **1** | نصب / نصبِ دوباره |
| **2** | تازه‌کردنِ رابطِ کاربری از `ui/` کنارِ اسکریپت |
| **3** | ری‌استارتِ سرویس (بعد از جایگزینیِ فایل) |
| **4** | تغییرِ پورت |
| **5** | تغییرِ رمز |
| **6** | حذف (نودها، لینک‌ها و تنظیمات در ردیس می‌مانند) |
| **0** | خروج |

گزینهٔ **2** را باید از داخلِ پوشهٔ بازشدهٔ ریلیز اجرا کنی، نه از `/opt/tnl-central`؛
اگر آنجا بزنی خودش می‌گوید چرا کاری نکرد.

## دستورهای تکی

نصب (ترمینال لازم دارد):

```bash
sudo python3 tnl-central.py --install
```

فقط تازه‌کردنِ رابطِ کاربری از `ui/` کنارِ اسکریپت:

```bash
sudo python3 tnl-central.py --install-ui
```

تغییرِ نام‌کاربری و رمزِ ورود:

```bash
sudo python3 tnl-central.py --set-pass
```

دیدنِ لاگِ سرویس:

```bash
journalctl -u tnl-central -f
```

## حذف

```bash
sudo python3 /opt/tnl-central/tnl-central.py
```

و گزینهٔ **6) Uninstall** را بزن. سرویس‌ها برداشته می‌شوند ولی دادهٔ ردیس
(`/var/lib/tnl-redis`) با نودها، لینک‌ها و تنظیمات سرِ جایش می‌ماند.

## داده

همهٔ دادهٔ پنل (نودها، تونل‌ها، پروکسی‌ها، تنظیمات، لاگ و آمار) در یک ردیسِ اختصاصی
(`tnl-redis.service`) است که فقط سوکتِ `/run/tnl-redis/redis.sock` را باز می‌کند و با
`appendfsync always` هر تغییر را قبل از جواب روی دیسک می‌نویسد؛ پنل بدونِ این تنظیم بالا
نمی‌آید. فایل‌های ردیس در `/var/lib/tnl-redis` هستند.

---

ایجنتِ نود 👉 [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
