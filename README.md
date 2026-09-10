# TUNNEL-MANAGER

## نصب

روی سرورِ مرکزی — Debian/Ubuntu با systemd، به‌عنوان root:

```bash
curl -fsSL -H "Authorization: token <TOKEN>" https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER/main/tnl-central.py -o /tmp/tnl-central.py && sudo python3 /tmp/tnl-central.py --install
```

`<TOKEN>` = یک GitHub PAT با دسترسیِ **Contents: Read** (این repo خصوصی است).

نصب‌کننده خودش پیش‌نیازها را می‌گیرد (`openssl`, `ca-certificates`, `iproute2`,
`openssh-client`, `sshpass`)، پورت و نام‌کاربری/رمز می‌پرسد، کلیدِ امضا را می‌سازد، سرویسِ
systemd را بالا می‌آورد، و هستهٔ `latest` و ایجنتِ نود را از پیش دانلود می‌کند.

بعدش: `http://<SERVER-IP>:<PORT>`

## بروزرسانی

```bash
curl -fsSL -H "Authorization: token <TOKEN>" https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER/main/tnl-central.py -o /tmp/tnl-central.py && sudo install -m755 /tmp/tnl-central.py /opt/tnl-central/tnl-central.py && sudo systemctl restart tnl-central
```

## دستورها

| دستور | کار |
|---|---|
| `sudo python3 tnl-central.py --install` | نصب (ترمینال لازم دارد) |
| `sudo python3 tnl-central.py --set-pass` | تغییرِ نام‌کاربری/رمزِ ورود |
| `sudo python3 tnl-central.py` | منویِ root: وضعیت / ری‌استارت / تغییرِ پورت / تغییرِ رمز / حذف |

## حذف

```bash
sudo python3 /opt/tnl-central/tnl-central.py    # گزینهٔ ۷) Uninstall
```

---

ایجنتِ نود 👉 [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
