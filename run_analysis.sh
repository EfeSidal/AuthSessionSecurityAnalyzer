#!/bin/bash

echo "----------------------------------------"
echo "Auth Session Security Analyzer Başlatılıyor"
echo "----------------------------------------"

# 1. Gerekli kütüphaneleri kontrol et
if ! python3 -c "import colorama" &> /dev/null; then
    echo "[!] Colorama eksik. Yükleniyor..."
    pip install colorama requests
fi

# 2. Kullanıcıdan input al
read -p "Analiz edilecek URL'yi girin: " target_url

# 3. Python aracını çalıştır
python3 src/main.py <<EOF
$target_url
EOF

echo "----------------------------------------"
echo "Analiz Tamamlandı. Rapor 'docs/' klasörüne kaydedilebilir."
echo "----------------------------------------"
