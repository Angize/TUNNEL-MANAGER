# TUNNEL-MANAGER

کنترل‌پنلِ وبِ مدیریتِ فلیتِ تونل. از یک داشبورد، تونل‌های رمزنگاری‌شدهٔ هسته و تونل‌های
کرنلی و پورت‌فوروارد را می‌سازی و مدیریت می‌کنی. مرکزی فقط کنترل‌کننده است — ترافیک
مستقیم بینِ دو نود جریان دارد، هرگز از این‌جا عبور نمی‌کند.

## پیش‌نیاز

| ابزار | برای چه |
|---|---|
| `python3` (3.7+) | اجرای پنل — بدونِ وابستگیِ خارجی (فقط stdlib) |
| `git` | دریافتِ کد |
| Linux + systemd | سرویسِ ماندگار |
| GitHub PAT | چون repo خصوصی است (دسترسیِ Contents: Read) |

## راه‌اندازی از صفر

روی سرورِ **مرکزی**:

```bash
# ۱) پیش‌نیازها (Debian/Ubuntu)
sudo apt update && sudo apt install -y python3 git

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
| `--install` | تنظیمِ کاربر/رمز/پورت + نصب و استارتِ سرویس |
| `--set-pass` | تغییرِ نام‌کاربری/رمزِ ورود |
| بروزرسانی | `sudo cp tnl-central.py /opt/tnl-central/tnl-central.py && sudo systemctl restart tnl-central` |

> ⚠️ HTTP ساده است و کوکیِ نشست قابلِ شنود — روی شبکهٔ مطمئن/VPN اجرا کن یا پشتِ TLS بگذار.

## قابلیت‌ها

| قابلیت | جزئیات |
|---|---|
| `core` | تونلِ رمزنگاری‌شدهٔ هسته — udp/tcp/raw/flux/ws، obfs/cover/FEC/جعلِ IP |
| kernel | تونلِ نودبه‌نود — VXLAN / GRE / SIT |
| forward | پورت‌فوروارد با چرخشِ چند مقصد |
| monitor | مانیتورینگِ زنده — CPU / RAM / دیسک / ترافیک |
| deploy | دانلود و push هسته + بروزرسانیِ ایجنتِ نودها، بدونِ SSH |
| UI | رابطِ فارسی، تمِ روشن/تیره |

---

ایجنتِ نود 👉 [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • مجوز 👉 [LICENSE](./LICENSE)
