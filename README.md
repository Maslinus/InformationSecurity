# RSA Encryption/Decryption System

## Описание
Этот код реализует систему безопасной передачи сообщений с использованием алгоритма RSA. Проект состоит из двух частей:
- Клиентской программы, которая шифрует и отправляет сообщения
- Серверной программы, которая генерирует ключи, принимает и расшифровывает сообщения

## Основные функции

### Генерация ключей RSA
- Использует тест Миллера-Рабина для генерации больших простых чисел
- Создает пары ключей (публичный и приватный) заданной длины (по умолчанию 512 бит)
- Поддерживает проверку взаимной простоты чисел

### Шифрование и дешифрование
- Реализует блочное шифрование/дешифрование сообщений
- Поддерживает кодирование сообщений в Base64
- Обрабатывает сообщения произвольной длины через разбиение на блоки

### Сетевое взаимодействие
- Серверная часть ожидает соединений на порту 5000
- Клиентская часть подключается к серверу по адресу 127.0.0.1:5000
- Обеспечивает безопасную передачу публичного ключа и зашифрованных сообщений

## Использование
1. Запустите серверную часть (`server_program()`)
2. Запустите клиентскую часть (`client_program()`)
3. Клиент автоматически отправит тестовое зашифрованное сообщение
4. Сервер примет, расшифрует и выведет сообщение

## Особенности
- Криптографически безопасная генерация случайных чисел
- Оптимизированное возведение в степень по модулю
- Автоматическая обработка ошибок декодирования
- Поддержка Unicode и мультиязычных сообщений

## Требования
- Python 3.x
- Библиотеки: socket, secrets, math, sympy, base64, random
