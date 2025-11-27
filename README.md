Mini-App de Citas/Turnos (Appointments) – C++ CLI

Este proyecto implementa:

Registro e inicio de sesión de usuarios

Roles: client y staff

CRUD de citas

Manejo de logs y auditoría

Validación de entrada

Hashing de contraseñas con SHA-256

Persistencia en archivos .txt

Prácticas de Secure Coding

1. Requisitos para correr el proyecto
 1.1 Compilador C++ (g++)

Necesitas tener instalado MinGW-w64 (Winlibs).

Descarga recomendada:

https://winlibs.com/#download-release

La descarga puede variar de maquina a maquina pero el que usamos fue este

https://github.com/brechtsanders/winlibs_mingw/releases/download/15.2.0posix-13.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-15.2.0-mingw-w64ucrt-13.0.0-r3.7z

Asegura que descargues el ZIP que contenga:

x86_64

posix

seh

GCC 13.x o superior

Instalación:

Extraer el ZIP en:

C:\mingw64


Agregar al PATH:
Usando Windows + R escribir sysdm.cpl
Despues en esa ventana en "Advanced" ir a "Enviroment Variables"
Edit en "Path" , Luego New y pegas el path del .exe del ZIP que acabas de descargar. 
Si lo descargas de la manera se muestra en este Read.Me el path deberia ser el siguiente

C:\mingw64\winlibs-x86_64-posix-seh-gcc-13.x.x\mingw64\bin

Verificar instalación

Asegurarse!! de que luego de agregar el Path reiniciar Visual Studio Code para entonces.

En PowerShell:

g++ --version


Debe mostrar la versión de GCC.

2. Archivos necesarios

Crear un folder vacio y abrirlo en Visual Studio Code y crear el siguiente file

main.cpp y simplemente copiar y pegar el codigo que se encuentra en:
https://github.com/Vitols-code/Appointments/blob/main/main.cpp

3. Cómo compilar el programa

En la terminal dentro de la carpeta del proyecto, ejecutar:

g++ main.cpp -std=c++17 -o appointments.exe


Si no hay errores, se crea:

appointments.exe

4. Cómo ejecutar

En terminal:

.\appointments.exe


Verás el menú principal:

1) Register
2) Login
3) Salir
Elige:

5. Funcionamiento básico
 Registrar usuario

Username (sin espacios)

Password (min 6 caracteres)

Rol: client o staff

 Login

El sistema utiliza hashing SHA-256.

 Rol: client

Puede:

Crear su cita

Ver sus citas

Reprogramar (solo si faltan >= 24h)

Cancelar sus propias citas

Rol: staff

Puede:

Ver todas las citas

Crear citas para cualquier cliente

Reprogramar cualquier cita

Cancelar cualquier cita

Marcar asistencia (attended / no_show)

Ver el audit log

6. Formato de fecha aceptado

El programa usa el formato:

YYYY-MM-DD HH:MM


Ejemplos válidos:

2026-09-21 08:30
2026-09-21 14:45


Importante: la hora debe tener dos dígitos (04, 08, 14, etc.).

7. Archivos generados automáticamente
users.txt
username|sha256hash|role

appointments.txt
id|client|start_epoch|duration|status

audit.log

Registra:

acciones de usuarios

cambios en citas

errores y accesos

8. Seguridad aplicada

 Hashing de contraseñas
 Validación de entrada
 Anti-injection (no se concatena en estructuras sensibles)
 CSV sanitización
 Registro de auditoría
 Control de acceso por rol
 Demostración de overflow vs versión corregida

9. Cómo resetear el sistema

Basta con borrar:

users.txt

appointments.txt

audit.log

El programa los recrea automáticamente.
