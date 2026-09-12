# TUNNEL-MANAGER

## نصب

روی سرورِ مرکزی — Debian/Ubuntu با systemd، به‌عنوان root:

```bash
TOKEN=<TOKEN>
REPO=https://api.github.com/repos/Angize/TUNNEL-MANAGER
ASSET=$(curl -fsSL -H "Authorization: token $TOKEN" "$REPO/releases/latest" \
  | python3 -c "import json,sys;print([a['url'] for a in json.load(sys.stdin)['assets'] if a['name'].endswith('.tar.gz')][0])")
curl -fsSL -H "Authorization: token $TOKEN" -H "Accept: application/octet-stream" "$ASSET" -o /tmp/tnl.tgz
rm -rf /tmp/tnl && mkdir -p /tmp/tnl && tar xzf /tmp/tnl.tgz -C /tmp/tnl
cd /tmp/tnl && sudo python3 tnl-central.py --install
```

پنل دیگر یک فایلِ تنها نیست: رابطِ کاربری یک بیلدِ React است که کنارِ اسکریپت در `ui/`
می‌نشیند، و گیت‌هاب خودش می‌سازدش (ورک‌فلوی `release-panel` روی هر تگِ `v*`). به همین
دلیل نصب از **ریلیز** است نه از فایلِ خامِ `main`؛ نصب‌کننده `ui/` را در
`/opt/tnl-central/ui` می‌گذارد و اگر پیدایش نکند اجرا را متوقف می‌کند.

`<TOKEN>` = یک GitHub PAT با دسترسیِ **Contents: Read** (این repo خصوصی است).

نصب‌کننده خودش پیش‌نیازها را می‌گیرد (`openssl`, `ca-certificates`, `iproute2`,
`openssh-client`, `sshpass`)، پورت و نام‌کاربری/رمز می‌پرسد، کلیدِ امضا را می‌سازد، سرویسِ
systemd را بالا می‌آورد، و هستهٔ `latest` و ایجنتِ نود را از پیش دانلود می‌کند.

بعدش: `http://<SERVER-IP>:<PORT>`

## بروزرسانی

همان خط‌های بالا تا `tar xzf`، بعد:

```bash
cd /tmp/tnl
sudo install -m755 tnl-central.py /opt/tnl-central/tnl-central.py
sudo python3 tnl-central.py --install-ui
sudo systemctl restart tnl-central
```

اگر فقط رابطِ کاربری عوض شده، `--install-ui` به‌تنهایی کافی است و ری‌استارت لازم
نیست — فایل‌ها از روی دیسک سرو می‌شوند. نامِ فایل‌های `ui/assets/` هش‌دار است، پس
مرورگر نسخهٔ تازه را می‌گیرد و کهنه را از کش نمی‌خواند.

## دستورها

| دستور | کار |
|---|---|
| `sudo python3 tnl-central.py --install` | نصب (ترمینال لازم دارد) |
| `sudo python3 tnl-central.py --install-ui` | فقط تازه‌کردنِ رابطِ کاربری از `ui/`ِ کنارِ اسکریپت |
| `sudo python3 tnl-central.py --set-pass` | تغییرِ نام‌کاربری/رمزِ ورود |
| `sudo python3 tnl-central.py` | منویِ root: وضعیت / ری‌استارت / تغییرِ پورت / تغییرِ رمز / حذف |

## حذف

```bash
sudo python3 /opt/tnl-central/tnl-central.py    # گزینهٔ ۷) Uninstall
```

---

ایجنتِ نود 👉 [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
