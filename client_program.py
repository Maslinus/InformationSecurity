import socket
import secrets
from math import gcd
from sympy import mod_inverse
import base64
import random

# Алгоритм Миллера-Рабина для проверки числа на простоту
def miller_rabin_test(n, k):
    def is_compos(a):
        x = pow(a, d, n)
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
    #Вычисление функции Эйлера.
    phi = (p - 1) * (q - 1)

    #Открытая экспонента
    e = 65537
    #Проверка взаимной простоты e и phi. Если они не взаимно просты, выбирается новое e.
    while gcd(e, phi) != 1:
        e = secrets.randbelow(phi - 1) + 1

    # мутльтикапликативная обратная к числу е (закрытая экспонента)
    d = mod_inverse(e, phi)

    #Возвращает оба ключа - публичные (e, n) и приватные (d, n).
    return (e, n), (d, n)

def block_encrypt(message, public_key, block_size):
    e, n = public_key
    #Создание списка блоков сообщения. Каждый блок имеет размер block_size - 1, чтобы учесть возможные байты заполнения.
    blocks = [message[i:i + block_size - 1] for i in range(0, len(message), block_size - 1)]
    encrypted_blocks = []

    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        encrypted_int = pow(block_int, e, n) #  шифрование числа с возведения в степень по модулю
        encrypted_blocks.append(encrypted_int.to_bytes(block_size, byteorder='big'))

    #Объединение всех зашифрованных блоков в одну последовательность байтов и возврат результата.
    return b''.join(encrypted_blocks)

def client_program():
    #создается сокет клиента 
    client_socket = socket.socket()
    client_socket.connect(('127.0.0.1', 5000))

    data = client_socket.recv(1024)
    e = int.from_bytes(data, byteorder='big')
    data = client_socket.recv(1024)
    n = int.from_bytes(data, byteorder='big')

    public_key = (e, n)

    message = "This is an encrypted message. Это зашифрованное сообщение."
    message_bytes = message.encode('utf-8') # Сообщение кодируется в байты
    message_base64 = base64.b64encode(message_bytes)
    print(message_base64)
    encrypted_message = block_encrypt(message_base64, public_key, (n.bit_length() + 7) // 8)

    client_socket.send(encrypted_message) # Отправка зашифрованного сообщения
    client_socket.close()

if __name__ == '__main__':
    client_program()
