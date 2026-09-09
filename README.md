# TUNNEL-MANAGER

کنترل‌پنلِ وبِ مدیریتِ فلیتِ تونل. از یک داشبورد، تونل‌های رمزنگاری‌شدهٔ هسته و تونل‌های
کرنلی و پورت‌فوروارد را می‌سازی و مدیریت می‌کنی. مرکزی فقط کنترل‌کننده است — ترافیک
مستقیم بینِ دو نود جریان دارد، هرگز از این‌جا عبور نمی‌کند. یک فایلِ Pythonِ تک‌فایل
(فقط stdlib) که سرویسِ systemd می‌شود.

## پیش‌نیاز

| ابزار | برای چه |
|---|---|
| `python3` (3.7+) | اجرای پنل — بدونِ وابستگیِ خارجی (فقط stdlib) |
| `openssl` | امضای RSAِ push کد به نودها |
| `ssh`/`sshpass` | افزودنِ خودکارِ نود روی SSH (اختیاری) |
| `git` | دریافتِ کد |
| Linux + systemd | سرویسِ ماندگار |
| GitHub PAT | چون repo خصوصی است (دسترسیِ Contents: Read) |

## راه‌اندازی از صفر

روی سرورِ **مرکزی**:

```bash
# ۱) پیش‌نیازها (Debian/Ubuntu)
sudo apt update && sudo apt install -y python3 git openssl sshpass

# ۲) دریافتِ کد (repo خصوصی → با توکن)
git clone https://<TOKEN>@github.com/Angize/TUNNEL-MANAGER.git
cd TUNNEL-MANAGER
# یا تک‌فایل بدونِ git:
# curl -fsSL -H "Authorization: token <TOKEN>" \
#   https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER/main/tnl-central.py -o tnl-central.py

# ۳) نصب (کاربر/رمز/پورت می‌پرسد، سرویسِ systemd می‌سازد و استارت می‌کند)
sudo python3 tnl-central.py --install

# ۴) ورود از مرورگر:  http://<SERVER-IP>:<PORT>
```

`<TOKEN>` = یک GitHub PAT با دسترسیِ **Contents: Read**.

| دستور | کار |
|---|---|
| `--install` | تنظیمِ کاربر/رمز/پورت + نصب و استارتِ سرویس (نسخهٔ `latest` هسته را هم pre-stage می‌کند) |
| `--set-pass` | تغییرِ نام‌کاربری/رمزِ ورود |
| `--serve` | اجرای سرورِ وب (سرویسِ systemd همین را صدا می‌زند) |
| بدونِ آرگومان | منویِ تعاملیِ root (وضعیت/ری‌استارت/تغییرِ پورت/تغییرِ رمز/حذف) |
| بروزرسانی | `sudo cp tnl-central.py /opt/tnl-central/tnl-central.py && sudo systemctl restart tnl-central` |

> ⚠️ پنل روی HTTPِ ساده است و کوکیِ نشست و توکنِ کنترلِ نود قابلِ شنودند — روی شبکهٔ
> مطمئن/VPN اجرا کن یا پشتِ TLS بگذار. برای اعتمادِ `X-Forwarded-For` باید `tls` و
> `trusted_proxies` تنظیم شوند.

## قابلیت‌ها

| قابلیت | جزئیات |
|---|---|
| `core` | تونلِ رمزنگاری‌شدهٔ هسته — `udp`/`tcp`/`raw`/`ws`، همراه با obfs / cover(REALITY) / FEC / جعلِ IP / ECH / حاملِ CDN (ws/http/grpc) / SNI-split / fake-desync |
| kernel | تونلِ نودبه‌نود — VXLAN / GRE / SIT / IPIP / L2TPv3 / FOU / IPsec |
| forward | پورت‌فوروارد با چرخشِ چند مقصد |
| poolها | مدیریتِ زندهٔ poolِ چرخشیِ edge (IP×SNI) و poolِ مقصد/مبدأ — probe، انتخاب/pin، auto-burn، warm-standby |
| deploy | دانلود و push هسته + بروزرسانیِ ایجنتِ نودها، **بدونِ SSH**، با امضای RSA |
| افزودنِ نود | نصبِ خودکارِ ایجنت روی سرورِ نود از راهِ SSH (بدونِ نصبِ دستی) |
| monitor | مانیتورینگِ زنده — CPU / RAM / دیسک / ترافیک / uptime |
| events | لاگِ زندهٔ رویدادها (قطع/وصل/چرخش/burn/ECH) با کدهای دلیلِ ماشینی |
| self-heal | خودترمیمیِ ECH (کشفِ مجدد روی DoH) و آشتیِ خودکارِ تونل روی تغییرِ IP (حالتِ `auto`/`alert`) |
| UI | رابطِ فارسی، تمِ روشن/تیره، هدرهای امنیتی + CSRF + محدودسازیِ ورودِ ناموفق |

## امنیت (خلاصه)

- نشستِ **HMAC-امضاشدهٔ بدونِ‌حالت** (کوکیِ `tnl_session`, `HttpOnly; SameSite=Strict`)، رمز با PBKDF2 (۱۵۰k دور)، محدودسازیِ ورود (۸ خطا / ۳۰۰ ثانیه / IP).
- هر endpointِ تغییردهنده POST + هدرِ CSRF (`X-Requested-With: tnl-central`) می‌خواهد.
- push کد به نودها **مستقل از کانالِ ساده** با امضای RSA-2048 تأیید می‌شود؛ کلیدِ عمومی
  پیش از هر push به نود داده می‌شود و نود fail-closed راستی‌آزمایی می‌کند.
- پنل ترافیک را حمل نمی‌کند و PSKِ تونل‌ها را پیش از ارسال به مرورگر حذف می‌کند.

---

ایجنتِ نود 👉 [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
