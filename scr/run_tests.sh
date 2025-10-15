#!/bin/bash

# Проверка, собран ли проект
if [ ! -f build/toruscsidh ]; then
    echo "Ошибка: проект не собран. Сначала выполните build.sh"
    exit 1
fi

# Запуск тестов
echo "===== ЗАПУСК ТЕСТОВ TORUSCSIDH ====="
cd build
./toruscsidh
