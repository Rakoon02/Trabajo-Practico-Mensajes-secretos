import doctest
from tkinter import *
from tkinter import messagebox

def cifrado_cesar(mensaje, clave):
    #Cifra o descifra un mensaje usando el cifrado Cesar con la clave proporcionada.
    """
    >>> cifrado_cesar("Hola Mundo", 3)
    'Krod Pxqgr'
    >>> cifrado_cesar("abcXYZ", 2)
    'cdeZAB'
    >>> cifrado_cesar("12345", 4)
    '56789'
    >>> cifrado_cesar("a1b2c3", 1)
    'b2c3d4'
    >>> cifrado_cesar("Python!", 5)
    'Udymts!'
    >>> cifrado_cesar("Cesar 2025", 10)
    'Mockb 2025'
    >>> cifrado_cesar("Prueba #1", 7)
    'Wyblih #8'
    >>> cifrado_cesar("Zz9", 1)
    'Aa0'
    >>> cifrado_cesar("Español", 4)
    'Iwtessp'
    >>> cifrado_cesar("OpenAI 2025", 13)
    'BcraNV 5358'
    """
    mensaje_cifrado = ""
    clave = int(clave)
    for char in mensaje:
        if char.isupper():
            mensaje_cifrado += chr((ord(char) - ord('A') + clave) % 26 + ord('A'))
        elif char.islower():
            mensaje_cifrado += chr((ord(char) - ord('a') + clave) % 26 + ord('a'))
        elif char.isdigit():
            mensaje_cifrado += chr((ord(char) - ord('0') + clave) % 10 + ord('0'))
        else:
            mensaje_cifrado += char

    return mensaje_cifrado

def cifrado_atbash(texto):
    #Cifra o descifra un mensaje usando el cifrado Atbash.
    """
    >>> cifrado_atbash("Hola Mundo")
    'sLOZ nFMWL'
    >>> cifrado_atbash("abcXYZ")
    'ZYXcba'
    >>> cifrado_atbash("12345")
    '87654'
    >>> cifrado_atbash("a1b2c3")
    'Z8Y7X6'
    >>> cifrado_atbash("Python!")
    'kBGSLM!'
    >>> cifrado_atbash("Cesar 2025")
    'xVHZI 7974'
    >>> cifrado_atbash("Prueba #1")
    'kIFVYZ #8'
    >>> cifrado_atbash("Zz9")
    'aA0'
    >>> cifrado_atbash("Español")
    'vHKZñLO'
    >>> cifrado_atbash("OpenAI 2025")
    'lKVMzr 7974'
    """
    resultado = ""
    for char in texto:
        if 'A' <= char <= 'Z':
            nuevo = chr(ord('Z') - (ord(char) - ord('A')))
            resultado += nuevo.lower()
        elif 'a' <= char <= 'z':
            nuevo = chr(ord('z') - (ord(char) - ord('a')))
            resultado += nuevo.upper()
        elif '0' <= char <= '9':
            nuevo = chr(ord('9') - (ord(char) - ord('0')))
            resultado += nuevo
        else:
            resultado += char
    return resultado

def crear_ventana():
    #Crea una ventana de bienvenida a la aplicacion.
    raiz=Tk()
    raiz.title("TP Grupal Parte 1 - Grupo: SantiDom")
    raiz.geometry("500x200")
    raiz.iconbitmap("icon_eye.ico")
    raiz.config(bg= "grey")

    mi_frame = Frame(raiz, width=500, height=200)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    label_bienvenida = Label(mi_frame, text="Bienvenido a la aplicación de mensajes secretos del grupo SantiDom.\nPara continuar presione continuar, de lo contrario cierre la ventana", bg="gray", padx="4", pady="8")
    label_bienvenida.grid(row=0, column=0, columnspan=2)

    boton_continuar = Button(mi_frame, text="Continuar", command=ventana_cifrado)
    boton_continuar.grid(row=1, column=0, columnspan=2, pady=10)

    label_integrantes = Label(mi_frame, text="Construída por: Santiago Dominguez", bg="gray", padx="4", pady="8", justify="left")
    label_integrantes.grid(row=2, column=0, columnspan=2)

    raiz.mainloop()

def ventana_cifrado():
    #Crear una segunda ventana donde el usuario puede esscribir un mensaje y luego cifrar o descifrarlo.
    ventana_cifrado = Toplevel()
    ventana_cifrado.title("Cifrado y Descifrado de Mensajes")
    ventana_cifrado.resizable(0,0)
    ventana_cifrado.geometry("700x350")
    ventana_cifrado.iconbitmap("icon_eye.ico")
    ventana_cifrado.config(bg= "gray")

    mi_frame = Frame(ventana_cifrado, width=700, height=350)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    resultado_var = StringVar()

    Label(mi_frame, text="Mensaje:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_mensaje = Entry(mi_frame, width=50)
    cuadro_mensaje.grid(row=0, column=1, columnspan=1)

    Label(mi_frame, text="Clave de Cifrado:", bg="gray", padx=0, pady=8).grid(row=1, column=1, sticky="w")
    cuadro_clave = Entry(mi_frame, width=10)
    cuadro_clave.grid(row=1, column=1, sticky="e")

    Label(mi_frame, text="Resultado:", bg="gray", padx=2, pady=8).grid(row=5, column=0, sticky="e")
    resultado_label = Label(mi_frame, textvariable=resultado_var, bg="white", width=50, anchor="w")
    resultado_label.grid(row=5, column=1, columnspan=1)

    boton_cesar = Button(mi_frame, text="Cifrar mensaje César", command=lambda: mostrar_resultado(resultado_var, cifrado_cesar(cuadro_mensaje.get(), cuadro_clave.get())))
    boton_cesar.grid(row=1, column=0, pady=5)
    
    boton_atbash = Button(mi_frame, text="Cifrar mensaje Atbash", command=lambda: mostrar_resultado(resultado_var, cifrado_atbash(cuadro_mensaje.get())))
    boton_atbash.grid(row=3, column=0, pady=5)

    boton_descifrar_cesar = Button(mi_frame, text="Descifrar mensaje César", command=lambda: mostrar_resultado(resultado_var, cifrado_cesar(cuadro_mensaje.get(), -int(cuadro_clave.get()))))
    boton_descifrar_cesar.grid(row=2, column=0, pady=5)

    boton_descifrar_atbash = Button(mi_frame, text="Descifrar mensaje Atbash", command=lambda: mostrar_resultado(resultado_var, cifrado_atbash(cuadro_mensaje.get())))
    boton_descifrar_atbash.grid(row=4, column=0, pady=5)

def mostrar_resultado(resultado_var, resultado):
    #Muestra el resultado en el entry correspondiente
    resultado_var.set(resultado)

def main():
    crear_ventana()
    print(doctest.testmod())

if __name__ == "__main__":
    doctest.testmod()
    
main()