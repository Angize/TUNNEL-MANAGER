<div align="center">

# 🌐 tnl-central

**کنترل‌پنلِ وبِ مدیریتِ فلیتِ تونل**
ساخت و مدیریتِ تونل‌های نودبه‌نود (VXLAN / GRE / SIT) و پورت‌فوروارد، از یک داشبورد.

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-systemd-333?logo=linux&logoColor=white)
![deps](https://img.shields.io/badge/deps-none-2ea875)

</div>

---

## ⚡ نصب

روی سرورِ **مرکزی**:

```bash
git clone https://github.com/Angize/TUNNEL-MANAGER.git
cd TUNNEL-MANAGER && sudo python3 tnl-central.py --install
```

یوزر/پسورد/پورت را می‌پرسد و پنل را راه می‌اندازد؛ بعد آدرسِ پنل چاپ می‌شود.

**بروزرسانیِ نصبِ موجود:**
```bash
sudo cp tnl-central.py /opt/tnl-central/tnl-central.py && sudo systemctl restart tnl-central
```

---

## ✨ قابلیت‌ها

- 🧩 تونلِ نودبه‌نود — VXLAN / GRE / SIT
- 🔀 پورت‌فوروارد با چرخشِ چند مقصد
- 📊 مانیتورینگِ زنده — CPU / RAM / دیسک / ترافیک
- 🩹 خودترمیمی هنگام تغییرِ آی‌پیِ نود
- 🔄 بروزرسانیِ ایجنتِ نودها از پنل، بدونِ SSH
- 🎨 رابطِ فارسی، تمِ روشن/تیره

> ترافیکِ تونل مستقیم بینِ دو نود جریان دارد؛ مرکزی فقط فرمان می‌دهد.

---

<div align="center">

ایجنتِ نود 👉 [**tnl-node**](https://github.com/Angize/TUNNEL-MANAGER-NODE) • مجوز 👉 [LICENSE](./LICENSE)

</div>
