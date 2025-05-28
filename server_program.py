import socket
import secrets
from math import gcd
from sympy import mod_inverse
import base64
import binascii
import random

# Алгоритм Миллера-Рабина для проверки числа на простоту
def miller_rabin_test(n, k):
    def is_compos(a):
        x = pow(a, d, n) # Вычисление степени a по модулю n и присвоение результата переменной x.
        if x == 1 or x == n - 1:
            return False
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True

    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        if is_compos(a):
            return False
    return True

#генерирует случайное число длиной bits 
#(помогает создавать потенциально простые числа с заданным количеством битов, гарантируя их нечетность.)
def generate_prime_candidate(bits):
    p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    return p

#создает потенциально простое число кандидата p
def generate_prime(bits, k=40):
    p = generate_prime_candidate(bits)
    while not miller_rabin_test(p, k):
        p = generate_prime_candidate(bits)
    return p

#создает ключи RSA - закрытый и открытый
def generate_rsa_keys(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    #Умножение этих чисел для определения модуля n.
    n = p * q
    #Вычисление функции Эйлера phi(n) = (p - 1) * (q - 1).
    phi = (p - 1) * (q - 1)

    e = 65537
    #Проверка взаимной простоты e и phi. Если они не взаимно просты, выбирается новое e.
    while gcd(e, phi) != 1:
        e = secrets.randbelow(phi - 1) + 1

    # мутльтикапликативная обратная к числу е (закрытая экспонента)
    d = mod_inverse(e, phi)

    #Возвращает оба ключа - публичные (e, n) и приватные (d, n).
    return (e, n), (d, n)

def block_decrypt(encrypted_message, private_key, block_size):
    d, n = private_key
    blocks = [encrypted_message[i:i + block_size] for i in range(0, len(encrypted_message), block_size)]
    decrypted_blocks = []

    for block in blocks:
        r = int.from_bytes(block, byteorder='big')
        h = pow(r, d, n)
        h_bytes = h.to_bytes((h.bit_length() + 7) // 8, byteorder='big').rjust(block_size - 1, b'\x00')
        decrypted_blocks.append(h_bytes)

    return b''.join(decrypted_blocks).rstrip(b'\x00')

def server_program():
    #Создание сокета сервера
    server_socket = socket.socket()
    server_socket.bind(('0.0.0.0', 5000))
    #Слушает входящие соединения(максимум одно)
    server_socket.listen(1)
    conn, address = server_socket.accept()

    public_key, private_key = generate_rsa_keys(512)  # Пример размера ключа
    e, n = public_key

    b_e = (e.bit_length() + 7) // 8
    b_n = (n.bit_length() + 7) // 8
    e_bytes_string = e.to_bytes(b_e, byteorder='big')
    n_bytes_string = n.to_bytes(b_n, byteorder='big')
    conn.sendall(e_bytes_string)
    conn.sendall(n_bytes_string)

    encrypted_message = conn.recv(4096)
    block_size = (n.bit_length() + 7) // 8
    message_bytes = block_decrypt(encrypted_message, private_key, block_size)

    # Попробуем декодировать из Base64
    try:
        message = base64.b64decode(message_bytes).decode('utf-8')
    except (UnicodeDecodeError, binascii.Error):
        # Добавляем padding, если это необходимо
        padding = b'=' * ((4 - len(message_bytes) % 4) % 4)
        try:
            message = base64.b64decode(message_bytes + padding).decode('utf-8')
        except (UnicodeDecodeError, binascii.Error):
            message = message_bytes.decode('utf-8', errors='ignore')

    print("Received and decrypted message:", message)
    conn.close()

if __name__ == '__main__':
    server_program()
