#!/bin/bash

echo "----------------------------------------"
echo "Auth Session Security Analyzer Başlatılıyor"
echo "----------------------------------------"

# Rapor dosyasının adı (tarih ve saat ile)
REPORT_FILE="docs/analiz_raporu_$(date +%F_%H-%M).txt"

# Kullanıcıdan URL al
read -p "Analiz edilecek URL'yi girin: " target_url

# Python'u çalıştır, çıktıyı hem ekrana (tee) hem dosyaya yaz
# Winpty komutu Git Bash'te python'un donmasını engeller
echo "Hedef: $target_url"
echo "----------------------------------------" | tee -a "$REPORT_FILE"

# Python scriptini çalıştır ve input'u gönder
python src/main.py <<EOF | tee -a "$REPORT_FILE"
$target_url
EOF

echo "----------------------------------------"
echo "Analiz Tamamlandı! Rapor şuraya kaydedildi: $REPORT_FILE"
echo "----------------------------------------"