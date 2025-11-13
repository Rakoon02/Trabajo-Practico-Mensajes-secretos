import doctest
from tkinter import *
from tkinter import ttk, messagebox

def crear_ventana():
    #Crea una ventana raiz de bienvenida a la aplicacion.
    raiz=Tk()
    raiz.title("TP Grupal Parte 1 - Grupo: SantiDom")
    raiz.geometry("500x200")
    raiz.iconbitmap("Trabajo_Extra/icon_eye.ico")
    raiz.config(bg= "grey")

    mi_frame = Frame(raiz, width=500, height=200)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    label_bienvenida = Label(mi_frame, text="Bienvenido a la aplicación de mensajes secretos del grupo SantiDom.\nPara continuar ingrese con su cuenta de usuario o cree una nueva, \nde lo contrario cierre la ventana", bg="gray", padx="4", pady="8")
    label_bienvenida.grid(row=0, column=0, columnspan=2)

    label_integrantes = Label(mi_frame, text="Construída por: Santiago Dominguez", bg="gray", padx="4", pady="8", justify="left")
    label_integrantes.grid(row=4, column=0, columnspan=2)

    boton_continuar = Button(mi_frame, text="Crear Usuario", command=ventana_registrar_usuario)
    boton_continuar.grid(row=1, column=0, columnspan=1, pady=10, sticky="w")

    boton_continuar = Button(mi_frame, text="Ingreso Usuario", command=ventana_ingresar_usuario)
    boton_continuar.grid(row=1, column=1, columnspan=1, pady=10, sticky="e")

    raiz.mainloop()

def ventana_registrar_usuario():
    #Crea una ventana de registro de usuario.
    ventana_registro = Toplevel()
    ventana_registro.title("Registro de Usuario")
    ventana_registro.resizable(0,0)
    ventana_registro.geometry("500x250")
    ventana_registro.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana_registro.config(bg= "grey")

    mi_frame = Frame(ventana_registro, width=500, height=250)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    Label(mi_frame, text="Nombre de Usuario:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_usuario = Entry(mi_frame, width=30)
    cuadro_usuario.grid(row=0, column=1)

    Label(mi_frame, text="Clave de Usuario:", bg="gray", padx=2, pady=8).grid(row=1, column=0, sticky="e")
    cuadro_clave = Entry(mi_frame, width=30, show="*")
    cuadro_clave.grid(row=1, column=1)

    Label(mi_frame, text="Seleccione una Pregunta de Seguridad:", bg="gray", padx=2, pady=8).grid(row=2, column=0, sticky="e")
    
    preguntas = leer_archivo_csv("Trabajo_Extra/preguntas.csv")
    if preguntas is None:
        messagebox.showerror("Error", "No se encontró el archivo preguntas.csv")
        ventana_registro.destroy()
        return
    

    combo_preguntas = ttk.Combobox(mi_frame, values=[p[1] for p in preguntas], state="readonly", width=27)
    combo_preguntas.grid(row=2, column=1)
    if preguntas:
        combo_preguntas.current(0)

    Label(mi_frame, text="Respuesta:", bg="gray", padx=2, pady=8).grid(row=3, column=0, sticky="e")
    cuadro_respuesta = Entry(mi_frame, width=30)
    cuadro_respuesta.grid(row=3, column=1)

    boton_registrar = Button(mi_frame, text="Registrar", command=lambda: validar_y_registrar(cuadro_usuario, cuadro_clave, combo_preguntas, cuadro_respuesta, preguntas, ventana_registro))
    boton_registrar.grid(row=4, column=0, columnspan=2, pady=20)

def validar_y_registrar(usuario_entry, clave_entry, pregunta_combobox, respuesta_entry, preguntas, ventana):
    #Valida los datos ingresados y registra el usuario si son correctos.
    usuario = usuario_entry.get().strip()
    clave = clave_entry.get().strip()
    pregunta_texto = pregunta_combobox.get()
    respuesta = respuesta_entry.get().strip()

    if not usuario or not clave or not respuesta:
        messagebox.showwarning("Advertencia", "Por favor, complete todos los campos.")
        return

    if usuario_existe(usuario):
        messagebox.showerror("Error", "Identificador en uso. Elija otro nombre de usuario.")
        return
    
    if usuario_valido(usuario) == False:
        messagebox.showerror("Error", "El identificador del usuario no es válido.\nDebe tener entre 5 y 15 caracteres y solo puede contener letras, números, '_', '-', '.'")
        return

    if clave_valida(clave) == False:
        messagebox.showerror("Error", "La clave del usuario no es válida.\nDebe tener entre 4 y 8 caracteres, incluir al menos una letra mayúscula, una letra minúscula, un número, y uno de los siguientes caracteres: '_', '-', '#', '*'. Además, no puede haber caracteres repetidos adyacentes.")
        return

    id_pregunta = ""
    i = 0
    while i < len(preguntas) and id_pregunta == "":
        p = preguntas[i]
        if p[1] == pregunta_texto:
            id_pregunta = p[0]
        i += 1

    registrar_usuario(usuario, clave, id_pregunta, respuesta, ventana)

def registrar_usuario(usuario, clave, id_pregunta, respuesta, ventana):
    #Registra el usuario en el archivo CSV.
    try:
        with open("Trabajo_Extra/datos_usuarios.csv", "a") as archivo:
            archivo.write(f"{usuario},{clave},{id_pregunta},{respuesta},0\n")
        messagebox.showinfo("Éxito", "Usuario registrado correctamente.")
        ventana.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar el usuario.\n{e}")

def leer_archivo_csv(ruta):
    #Lee un archivo CSV y devuelve una lista de listas.
    datos = []
    try:
        with open(ruta, "r") as archivo:
            for linea in archivo:
                linea = linea.strip()
                if linea:
                    datos.append(linea.split(","))
    except FileNotFoundError:
        datos = None
    return datos

def usuario_existe(identificador):
    #Verifica si un usuario ya existe en el archivo CSV.
    usuarios = leer_archivo_csv("Trabajo_Extra/datos_usuarios.csv")
    existe = False
    if usuarios is None:
        return False
    for fila in usuarios:
        if fila[0] == identificador:
            return True
    return False

def usuario_valido(identificador):
    #Valida si el nombre de usuario cumple con los requisitos.
    """
    >>> usuario_valido("user_1")
    True
    >>> usuario_valido("juan.perez")
    True
    >>> usuario_valido("abcde")
    True
    >>> usuario_valido("usuario_2025")
    True
    >>> usuario_valido("user-name")
    True
    >>> usuario_valido("abc")
    False
    >>> usuario_valido("usuario_demasiado_largo")
    False
    >>> usuario_valido("user!name")
    False
    >>> usuario_valido("user name")
    False
    >>> usuario_valido("abc@123")
    False
    """
    es_valido = True
    i = 0

    if 5 <= len(identificador) <= 15:
        while i < len(identificador) and es_valido:
            char = identificador[i]
            if not (char.isalnum() or char in ['_', '-', '.']):
                es_valido = False
            i += 1
    else:
        es_valido = False

    return es_valido

def clave_valida(clave):
    #Valida si la contraseña del usuario cumple con los requisitos.
    """
    >>> clave_valida("Aa1_")
    True
    >>> clave_valida("Ab2-9")
    True
    >>> clave_valida("A1a#*")
    True
    >>> clave_valida("aA1_")
    True
    >>> clave_valida("Zz9#")
    True
    >>> clave_valida("Aa11_")
    False
    >>> clave_valida("aa1_")
    False
    >>> clave_valida("AA1_")
    False
    >>> clave_valida("Aa__")
    False
    >>> clave_valida("Aa1")
    False
    >>> clave_valida("Aa1_abc91")
    False
    >>> clave_valida("Aa1@")
    False
    """
    es_valido = True
    i = 0

    if 4 <= len(clave) <= 8:
        tiene_mayuscula = False
        tiene_minuscula = False
        tiene_numero = False
        tiene_caracter_especial = False

        caracteres_especiales = ['_', '-', '#', '*']

        while i < len(clave) and es_valido:
            char = clave[i]

            if char.isupper():
                tiene_mayuscula = True
            elif char.islower():
                tiene_minuscula = True
            elif char.isdigit():
                tiene_numero = True
            elif char in caracteres_especiales:
                tiene_caracter_especial = True
            else:
                es_valido = False

            if i > 0 and clave[i] == clave[i - 1]:
                es_valido = False

            i += 1

        if not (tiene_mayuscula and tiene_minuscula and tiene_numero and tiene_caracter_especial):
            es_valido = False

    else:
        es_valido = False

    return es_valido

def mostrar_resultado(resultado_var, texto):
    #Muestra el texto en el texto dado
    resultado_var.set(texto)

def ventana_ingresar_usuario():
    #Crea la ventana de ingreso de usuario.
    ventana_ingreso = Toplevel()
    ventana_ingreso.title("Identificación para acceso")
    ventana_ingreso.resizable(0,0)
    ventana_ingreso.geometry("400x150")
    ventana_ingreso.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana_ingreso.config(bg= "grey")

    mi_frame = Frame(ventana_ingreso, width=400, height=150)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    Label(mi_frame, text="Nombre de Usuario:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_usuario = Entry(mi_frame, width=30)
    cuadro_usuario.grid(row=0, column=1)

    Label(mi_frame, text="Clave de Usuario:", bg="gray", padx=2, pady=8).grid(row=1, column=0, sticky="e")
    cuadro_clave = Entry(mi_frame, width=30, show="*")
    cuadro_clave.grid(row=1, column=1)

    boton_ingresar = Button(mi_frame, text="Ingresar", command=lambda: validacion_y_ingreso_usuario(cuadro_usuario, cuadro_clave, ventana_ingreso))
    boton_ingresar.grid(row=2, column=0, columnspan=2, pady=10)

    boton_recuperacion = Button(mi_frame, text="Recuperar Clave", command=lambda: ventana_recuperar_clave(cuadro_usuario.get().strip()))
    boton_recuperacion.grid(row=2, column=1, columnspan=2, pady=10, sticky="e")

def validacion_y_ingreso_usuario(usuario_entry, clave_entry, ventana):
    #Verifica que los datos ingresados sean correctos para permitir el ingreso.
    usuario = usuario_entry.get().strip()
    clave = clave_entry.get().strip()

    if not usuario or not clave:
        messagebox.showwarning("Advertencia", "Por favor, complete todos los campos.")
        return

    usuarios = leer_archivo_csv("Trabajo_Extra/datos_usuarios.csv")

    if usuarios is None or len(usuarios) == 0:
        messagebox.showerror(
            "Error",
            "No se encontraron usuarios registrados.\n"
            "Debe registrarse previamente o si olvidaste la clave, presiona 'Recuperar Clave'."
        )
        return

    usuario_encontrado = False
    clave_correcta = False

    i = 0
    total_usuarios = len(usuarios)

    while i < total_usuarios and not usuario_encontrado:
        fila = usuarios[i]
        if fila[0] == usuario:
            usuario_encontrado = True
            intentos = int(fila[4])
            if intentos >= 3:
                messagebox.showwarning("Usuario bloqueado", "Usuario bloqueado.")
                return
            if fila[1] == clave:
                clave_correcta = True
        i += 1

    if not usuario_encontrado or not clave_correcta:
        messagebox.showerror(
            "Error",
            "Identificador inexistente o clave errónea.\n"
            "Si no se encuentra registrado debe registrarse previamente\n"
            "o si olvidaste la clave presiona el botón recuperar clave."
        )
    else:
        messagebox.showinfo("Éxito", f"Ingreso exitoso.")
        ventana.destroy()
        ventana_cifrado(usuario)

def ventana_recuperar_clave(usuario):
    #Crea la ventana de recuperación de clave.
    datos = leer_archivo_csv("Trabajo_Extra/datos_usuarios.csv")
    usuario_datos = buscar_usuario(usuario, datos)

    if not usuario_datos:
        messagebox.showerror("Error", "Usuario no encontrado.")
        return

    nombre, clave, id_pregunta, respuesta_registrada, intentos = usuario_datos
    intentos = int(intentos)

    if intentos >= 3:
        messagebox.showwarning("Usuario bloqueado", "El usuario está bloqueado. Contacte al administrador.")
        return

    # Cargar preguntas desde CSV
    preguntas = leer_preguntas()
    pregunta_texto = preguntas.get(id_pregunta, "Pregunta de seguridad no registrada.")

    ventana_recuperacion = Toplevel()
    ventana_recuperacion.title("Recuperación Clave")
    ventana_recuperacion.resizable(0,0)
    ventana_recuperacion.geometry("400x150")
    ventana_recuperacion.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana_recuperacion.config(bg= "grey")

    mi_frame = Frame(ventana_recuperacion, width=400, height=150)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    Label(mi_frame, text="Pregunta de Seguridad:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_pregunta = Entry(mi_frame, width=30)
    cuadro_pregunta.grid(row=0, column=1)

    Label(mi_frame, text=pregunta_texto, bg="gray", width=30, anchor="w").grid(row=0, column=1)


    Label(mi_frame, text="Respuesta:", bg="gray", padx=2, pady=8).grid(row=1, column=0, sticky="e")
    cuadro_respuesta = Entry(mi_frame, width=30)
    cuadro_respuesta.grid(row=1, column=1)

    Button(mi_frame, text="Verificar", bg="lightblue", width=15,command=lambda: procesar_respuesta(usuario, cuadro_respuesta, ventana_recuperacion)).grid(row=2, column=1, pady=10)

def guardar_datos(datos):
    #Guarda los datos actualizados en el archivo CSV.
    with open("Trabajo_Extra/datos_usuarios.csv", "w") as f:
        for fila in datos:
            f.write(",".join(fila) + "\n")

def buscar_usuario(nombre, datos):
    #Busca un usuario por nombre y devuelve su fila.
    for fila in datos:
        if fila[0] == nombre:
            return fila
    return None

def actualizar_intentos(nombre, intentos, datos):
    #Actualiza el número de intentos fallidos para el usuario.
    for fila in datos:
        if fila[0] == nombre:
            fila[4] = str(intentos)
            break
    guardar_datos(datos)

def leer_preguntas(ruta="Trabajo_Extra/preguntas.csv"):
    #Lee las preguntas de seguridad desde el archivo CSV.
    filas = leer_archivo_csv(ruta)
    preguntas = {}
    if filas:
        for fila in filas:
            if fila[0] != "ID_Pregunta":
                preguntas[fila[0]] = fila[1]
    return preguntas

def verificar_respuesta(nombre, respuesta_ingresada):
    #Verifica los datos y corrobora que coincida con la registrada.
    datos = leer_archivo_csv("Trabajo_Extra/datos_usuarios.csv")
    if datos is None:
        messagebox.showerror("Error", "No se encontró el archivo preguntas.csv")
        return
    usuario = buscar_usuario(nombre, datos)

    if not usuario:
        return "Usuario no encontrado.", "error"

    nombre, clave, id_pregunta, respuesta_registrada, intentos = usuario
    intentos = int(intentos)

    if intentos >= 3:
        return "Usuario bloqueado.", "bloqueado"

    if respuesta_ingresada.lower() == respuesta_registrada.lower():
        actualizar_intentos(nombre, 0, datos)
        return f"Recuperación exitosa. Su clave es: {clave}", "ok"
    else:
        intentos += 1
        actualizar_intentos(nombre, intentos, datos)
        if intentos >= 3:
            return "Ha superado el máximo de intentos. Usuario bloqueado.", "bloqueado"
        else:
            return f"Respuesta incorrecta. Intentos restantes: {3 - intentos}", "error"

def procesar_respuesta(usuario, cuadro_respuesta, ventana):
    #Verifica la respuesta ingresada y muestra mensajes en la interfaz.
    respuesta_ingresada = cuadro_respuesta.get().strip()
    mensaje, estado = verificar_respuesta(usuario, respuesta_ingresada)

    if estado == "ok":
        messagebox.showinfo("Recuperación Exitosa", mensaje)
        ventana.destroy()
    elif estado == "bloqueado":
        messagebox.showwarning("Usuario bloqueado", mensaje)
        ventana.destroy()
    else:
        messagebox.showerror("Error", mensaje)

def ventana_cifrado(usuario_remitente):
    #Crear una ventana donde el usuario puede escribir un mensaje y luego cifrar o descifrarlo, enviar mensajes o consultar mensajes recibidos.
    ventana_cifrado = Toplevel()
    ventana_cifrado.title("Cifrado y Descifrado de Mensajes")
    ventana_cifrado.resizable(0,0)
    ventana_cifrado.geometry("700x350")
    ventana_cifrado.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana_cifrado.config(bg= "grey")

    mi_frame = Frame(ventana_cifrado, width=700, height=350)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    resultado_var = StringVar()

    Label(mi_frame, text="Mensaje:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_mensaje = Entry(mi_frame, width=50)
    cuadro_mensaje.grid(row=0, column=1, columnspan=3)

    Label(mi_frame, text="Clave de Cifrado:", bg="gray", padx=0, pady=8).grid(row=1, column=1, sticky="w")
    cuadro_clave = Entry(mi_frame, width=10)
    cuadro_clave.grid(row=1, column=1, sticky="e")

    Label(mi_frame, text="Resultado:", bg="gray", padx=2, pady=8).grid(row=5, column=0, sticky="e")
    resultado_label = Label(mi_frame, textvariable=resultado_var, bg="white", width=50, anchor="w")
    resultado_label.grid(row=5, column=1, columnspan=3)


    boton_cesar = Button(mi_frame, text="Cifrar mensaje César", command=lambda: mostrar_resultado(resultado_var, cifrado_cesar(cuadro_mensaje.get(), cuadro_clave.get())))
    boton_cesar.grid(row=1, column=0, pady=5)
    
    boton_atbash = Button(mi_frame, text="Cifrar mensaje Atbash", command=lambda: mostrar_resultado(resultado_var, cifrado_atbash(cuadro_mensaje.get())))
    boton_atbash.grid(row=3, column=0, pady=5)

    boton_descifrar_cesar = Button(mi_frame, text="Descifrar mensaje César", command=lambda: mostrar_resultado(resultado_var, cifrado_cesar(cuadro_mensaje.get(), -int(cuadro_clave.get()))))
    boton_descifrar_cesar.grid(row=2, column=0, pady=5)

    boton_descifrar_atbash = Button(mi_frame, text="Descifrar mensaje Atbash", command=lambda: mostrar_resultado(resultado_var, cifrado_atbash(cuadro_mensaje.get())))
    boton_descifrar_atbash.grid(row=4, column=0, pady=5)

    boton_enviar_cesar = Button(mi_frame, text="Enviar mensaje cifrado César", command=lambda: ventana_enviar_cesar(usuario_remitente))
    boton_enviar_cesar.grid(row=6, column=0, columnspan=1, pady=10, sticky="w")

    boton_enviar_atbash = Button(mi_frame, text="Enviar mensaje cifrado Atbash", command=lambda: ventana_enviar_atbash(usuario_remitente))
    boton_enviar_atbash.grid(row=6, column=1, columnspan=1, pady=10, sticky="e")

    boton_ver_mensajes = Button(mi_frame, text="Consultar mensajes recibidos", command=lambda: ventana_consultar_mensajes(usuario_remitente))
    boton_ver_mensajes.grid(row=6, column=2, columnspan=1, pady=10, sticky="e")

def ventana_enviar_cesar(usuario_remitente):
    #Crea la ventana para enviar un mensaje cifrado con el cifrado César.
    ventana = Toplevel()
    ventana.title("Enviar Mensaje Cifrado")
    ventana.resizable(0,0)
    ventana.geometry("500x250")
    ventana.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana.config(bg= "grey")

    mi_frame = Frame(ventana, width=500, height=250)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    Label(mi_frame, text="Destinatario:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_destinatario = Entry(mi_frame, width=50)
    cuadro_destinatario.grid(row=0, column=1, columnspan=3)

    Label(mi_frame, text="Clave de Cifrado César:", bg="gray", padx=2, pady=8).grid(row=1, column=0, sticky="e")
    cuadro_clave = Entry(mi_frame, width=10)
    cuadro_clave.grid(row=1, column=1, sticky="w")

    Label(mi_frame, text="Mensaje:", bg="gray", padx=2, pady=8).grid(row=2, column=0, sticky="e")
    cuadro_mensaje = Entry(mi_frame, width=50)
    cuadro_mensaje.grid(row=2, column=1, columnspan=3)

    Button(mi_frame, text="Enviar", bg="lightblue", width=15, command=lambda: enviar_mensaje_cesar(usuario_remitente, cuadro_clave.get().strip(), cuadro_destinatario.get().strip(), cuadro_mensaje.get().strip(), ventana)).grid(row=3, column=1, pady=10)

def ventana_enviar_atbash(usuario_remitente):
    #Crea la ventana para enviar un mensaje cifrado con el cifrado Atbash.
    ventana = Toplevel()
    ventana.title("Enviar Mensaje Cifrado")
    ventana.resizable(0,0)
    ventana.geometry("500x250")
    ventana.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana.config(bg= "grey")

    mi_frame = Frame(ventana, width=500, height=250)
    mi_frame.pack()
    mi_frame.config(bg="gray")

    Label(mi_frame, text="Destinatario:", bg="gray", padx=2, pady=8).grid(row=0, column=0, sticky="e")
    cuadro_destinatario = Entry(mi_frame, width=50)
    cuadro_destinatario.grid(row=0, column=1, columnspan=3)

    Label(mi_frame, text="Mensaje:", bg="gray", padx=2, pady=8).grid(row=1, column=0, sticky="e")
    cuadro_mensaje = Entry(mi_frame, width=50)
    cuadro_mensaje.grid(row=1, column=1, columnspan=3)

    Button(mi_frame, text="Enviar", bg="lightblue", width=15, command=lambda: enviar_mensaje_atbash(usuario_remitente, cuadro_destinatario.get().strip(), cuadro_mensaje.get().strip(), ventana)).grid(row=2, column=1, pady=10)

def obtener_clave_entero(clave_str):
    #Convierte la clave ingresada en un entero.
    try:
        return int(clave_str)
    except ValueError:
        messagebox.showerror("Error de clave", "Debe ingresar un número válido para la clave César.")
        return None

def enviar_mensaje_cesar(remitente, clave_str, destinatario, mensaje, ventana):
    #Envía un mensaje cifrado con el cifrado César. Agregandolo al archivo mensajes.csv.
    usuarios = leer_archivo_csv("Trabajo_Extra/datos_usuarios.csv")
    destinatarios_validos = [u[0].strip() for u in usuarios]

    if destinatario != "*" and destinatario not in destinatarios_validos:
        messagebox.showerror("Destinatario Inexistente", "El destinatario ingresado no existe.")
        return

    
    try:
        clave = int(clave_str)
    except ValueError:
        messagebox.showerror("Error de clave", "Debe ingresar un número válido para la clave César.")
        return

    mensaje_cifrado = cifrado_cesar(mensaje, clave)

    try:
        with open("Trabajo_Extra/mensajes.csv", "a") as f:
            f.write(f"{destinatario},{remitente},C{clave},{mensaje_cifrado}\n")
        messagebox.showinfo("Mensaje Enviado", "Mensaje Enviado")
        ventana.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo enviar el mensaje.\n{e}")

def enviar_mensaje_atbash(remitente, destinatario, mensaje, ventana):
    #Envía un mensaje cifrado con el cifrado Atbash. Agregandolo al archivo mensajes.csv.
    usuarios = leer_archivo_csv("Trabajo_Extra/datos_usuarios.csv")
    destinatarios_validos = [u[0] for u in usuarios]

    if destinatario != "*" and destinatario not in destinatarios_validos:
        messagebox.showerror("Destinatario Inexistente", "El destinatario ingresado no existe.")
        return

    mensaje_cifrado = cifrado_atbash(mensaje)

    try:
        with open("Trabajo_Extra/mensajes.csv", "a") as f:
            f.write(f"{destinatario},{remitente},A,{mensaje_cifrado}\n")
        messagebox.showinfo("Mensaje Enviado", "Mensaje Enviado")
        ventana.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo enviar el mensaje.\n{e}")

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

def ventana_consultar_mensajes(usuario):
    #Crea la ventana para consultar los mensajes recibidos por el usuario.
    ventana = Toplevel()
    ventana.title("Mensajes recibidos")
    ventana.geometry("600x400")
    ventana.iconbitmap("Trabajo_Extra/icon_eye.ico")
    ventana.config(bg="gray")

    frame = Frame(ventana, bg="gray", padx=10, pady=10)
    frame.pack(fill="both", expand=True)

    text_area = Text(frame, bg="gray31", width=70, height=20)
    text_area.pack(side="left", fill="both", expand=True, padx=(0,5))
    scrollbar = Scrollbar(frame, command=text_area.yview)
    scrollbar.pack(side="right", fill="y")
    text_area.config(yscrollcommand=scrollbar.set)

    mensajes = leer_mensajes_archivo()
    mensajes_todos, mensajes_usuario = filtrar_mensajes(mensajes, usuario)
    mensajes_para_mostrar = preparar_mensajes_para_mostrar(mensajes_todos, mensajes_usuario)
    for m in mensajes_para_mostrar:
        text_area.insert(END, f"{m['remitente']}: {m['mensaje']}\n")

def leer_mensajes_archivo():
    #Lee los mensajes desde el archivo mensajes.csv.
    mensajes = []
    try:
        with open("Trabajo_Extra/mensajes.csv", "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                partes = linea.split(",", 3)
                if len(partes) == 4:
                    mensajes.append({"destinatario": partes[0].strip(),"remitente": partes[1].strip(),"tipo": partes[2].strip(),"mensaje": partes[3].strip()})
    except FileNotFoundError:
        pass
    return mensajes

def filtrar_mensajes(mensajes, usuario):
    #Filtra los mensajes para obtener los dirigidos a todos y los dirigidos al usuario específico.
    mensajes_todos = []
    mensajes_usuario = []
    for m in mensajes:
        if m["destinatario"] == "*":
            mensajes_todos.append(m)
        elif m["destinatario"] == usuario:
            mensajes_usuario.append(m)
    return mensajes_todos, mensajes_usuario

def descifrar_mensaje(m):
    #Descifra un mensaje según su tipo de cifrado.
    if m["tipo"][0] == "C":
        clave = int(m["tipo"][1:])
        return cifrado_cesar(m["mensaje"], -clave)
    elif m["tipo"] == "A":
        return cifrado_atbash(m["mensaje"])
    else:
        return m["mensaje"]

def preparar_mensajes_para_mostrar(mensajes_todos, mensajes_usuario):
    #Prepara los mensajes para mostrarlos en la interfaz.
    mensajes_todos = [{"remitente": f"#{m['remitente']}", "mensaje": descifrar_mensaje(m)} for m in mensajes_todos]
    mensajes_usuario = [{"remitente": m['remitente'], "mensaje": descifrar_mensaje(m)} for m in mensajes_usuario]
    
    mensajes_todos.reverse()
    mensajes_usuario.reverse()
    
    return mensajes_todos + mensajes_usuario

def main():
    crear_ventana()
    print(doctest.testmod())

if __name__ == "__main__":
    doctest.testmod()
    
main()