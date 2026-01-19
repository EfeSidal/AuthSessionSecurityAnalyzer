#!/bin/bash

# Türkçe karakter sorununu çözer
export PYTHONIOENCODING=utf-8

echo "----------------------------------------"
echo "Auth Session Security Analyzer Başlatılıyor"
echo "----------------------------------------"

REPORT_FILE="docs/analiz_raporu_$(date +%F_%H-%M).txt"

# Kullanıcıdan URL al
read -p "Analiz edilecek URL'yi girin: " target_url

# URL'deki olası boşlukları temizle
target_url=$(echo "$target_url" | xargs)

echo "Hedef: $target_url"
echo "----------------------------------------" | tee -a "$REPORT_FILE"

# Python'u DOĞRUDAN argüman ile çalıştır (Hata riskini bitirir)
python src/main.py "$target_url" | tee -a "$REPORT_FILE"

echo "----------------------------------------"
echo "Analiz Tamamlandı! Rapor: $REPORT_FILE"
echo "----------------------------------------"