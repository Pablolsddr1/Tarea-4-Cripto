from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
import binascii

# obtencion datos de entrada
def solicitar_datos():
    clave = input("Ingrese la clave [ingrese clave de 1 a 32 caracteres]: ").encode('utf-8')
    print("Clave recibida.")
    iv = input("Ingrese el IV [ingrese clave de 1 a 32 caracteres]: ").encode('utf-8')
    print("IV recibido.")
    cif_text = input("Ingrese el texto a cifrar: ").encode('utf-8')
    print("Texto a cifrar recibido.")
    return clave, iv, cif_text

# Valida y ajusta clave 
def ajustar_clave(clave, longitud):
    # Muestra la clave original en hexadecimal
    print("Clave original (hex):", binascii.hexlify(clave).decode())
    
    if len(clave) < longitud:
        clave += get_random_bytes(longitud - len(clave))
        print("Clave ajustada (se añadieron bytes aleatorios):", binascii.hexlify(clave).decode())
    elif len(clave) > longitud:
        clave = clave[:longitud]
        print("Clave ajustada (se truncó a la longitud requerida):", binascii.hexlify(clave).decode())
    else:
        print("Clave ajustada (ya tenía la longitud requerida):", binascii.hexlify(clave).decode())
    
    print("Clave final (hex):", binascii.hexlify(clave).decode())
    return clave


# Ajuste de la clave e IV según el algoritmo
def procesar_datos(algoritmo):
    clave, iv, cif_text = solicitar_datos()
    
    if algoritmo == 'DES':
        clave = ajustar_clave(clave, 8)
        iv = ajustar_clave(iv, 8)
    elif algoritmo == '3DES':
        clave = ajustar_clave(clave, 24)
        iv = ajustar_clave(iv, 8)
    elif algoritmo == 'AES-256':
        clave = ajustar_clave(clave, 32)
        iv = ajustar_clave(iv, 16)
    return clave, iv, cif_text

# Cifrado y descifrado en CBC
def cifrar(clave, iv, cif_text, algoritmo):
    if algoritmo == 'DES':
        cipher = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == '3DES':
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == 'AES-256':
        cipher = AES.new(clave, AES.MODE_CBC, iv)
    
    block_size = cipher.block_size
    cif_text = cif_text + b' ' * (block_size - len(cif_text) % block_size)
    texto_cifrado = cipher.encrypt(cif_text)
    print(f"Texto cifrado ({algoritmo}):", binascii.hexlify(texto_cifrado).decode())
    return texto_cifrado

def descifrar(clave, iv, texto_cifrado, algoritmo):
    if algoritmo == 'DES':
        cipher = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == '3DES':
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == 'AES-256':
        cipher = AES.new(clave, AES.MODE_CBC, iv)
    
    texto_descifrado = cipher.decrypt(texto_cifrado).strip()
    print(f"Texto descifrado ({algoritmo}):", texto_descifrado.decode())
    return texto_descifrado

# Ejecución 
for algoritmo in ['DES', '3DES', 'AES-256']:
    print(f"\n--- Procesando {algoritmo} ---")
    clave, iv, cif_text = procesar_datos(algoritmo)
    texto_cifrado = cifrar(clave, iv, cif_text, algoritmo)
    descifrar(clave, iv, texto_cifrado, algoritmo)
