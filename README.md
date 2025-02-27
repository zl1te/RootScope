# RootScope

🌟 RootScope - Auditoría Avanzada de Escalada de Privilegios.
  

RootScope es una herramienta poderosa y avanzada escrita en Bash puro 🚀, diseñada para auditorías de seguridad y pruebas de penetración. Su misión: detectar y explotar vulnerabilidades de escalada de privilegios en sistemas Linux, macOS y Windows (vía WSL, Git Bash o Cygwin). Genera un reporte detallado en PDF 📑 con todas las vulnerabilidades encontradas, perfecto para pentesters, administradores de sistemas y profesionales de ciberseguridad.

⚠️ Advertencia Legal: Usa RootScope solo en entornos donde tengas permiso explícito. El uso no autorizado es ilegal y va contra las leyes de seguridad informática.

✨ Características Principales
Multiplataforma: Funciona en Linux 🐧, macOS 🍎 y Windows 🪟.
Enumeración Completa: Analiza SUID, sudo, tareas programadas, kernel, red, grupos, backdoors, logs, software vulnerable, políticas, bibliotecas, sesiones, montajes y rootkits 🔍.
Explotación Automática: Crea payloads multi-etapa y los inyecta en entornos vulnerables 💣.
Persistencia: Añade mecanismos para mantener el acceso (cron, registro) 🔒.
Reporte en PDF: Genera un informe estructurado y visualmente atractivo 📊.
🛠️ Requisitos
Sistemas Operativos:
Linux (distribuciones modernas).
macOS.
Windows (con WSL, Git Bash o Cygwin).
Herramientas Básicas: Bash, comandos nativos (netstat, wmic, find, etc.).
Para el PDF (opcional):
pandoc y pdflatex 📜.
Linux: sudo apt install pandoc texlive.
macOS: brew install pandoc basictex.
Windows: Instala pandoc y MiKTeX en WSL/Git Bash.
🚀 Instalación
¡Configura PrivAudit en segundos! Sigue estos pasos:

Clona el Repositorio:
'''
bash
Wrap
Copy
'''
git clone https://github.com/[tu-usuario]/PrivAudit.git
cd PrivAudit
Dale Permisos:
bash
Wrap
Copy
chmod +x privaudit.sh
(Opcional) Instala Dependencias para PDF:
bash
Wrap
Copy
# Linux
sudo apt install pandoc texlive
# macOS
brew install pandoc basictex
# Windows (en WSL)
sudo apt install pandoc texlive


## Vulnerabilidades Detectadas
- **INFO**: Sistema operativo detectado: Linux
- **ALERTA**: /usr/bin/passwd explotable con técnicas avanzadas.
- **ALERTA**: Servicio privilegiado expuesto: sshd en 0.0.0.0:22
🔍 Funcionalidades Avanzadas
Enumeración Exhaustiva
SUID/SGID: Binarios con permisos especiales 🕵️‍♂️.
Kernel/SO: Versiones vulnerables (ej., Dirty COW, CVE-2015-1701) ⚙️.
Red: Servicios expuestos y reglas de firewall laxas 🌐.
Backdoors: Cuentas ocultas y procesos sospechosos 👻.
Software: Versiones vulnerables instaladas (ej., OpenSSH, Adobe) 📦.
Políticas: Contraseñas débiles y configuraciones inseguras 🔑.
Rootkits: Detección de archivos ocultos 🕳️.
Explotación
Payloads Multi-Etapa: Crea usuarios y asegura persistencia 🎯.
Variables de Entorno: Inyecta código en $PATH escribible 🛠️.
Bibliotecas: Analiza bibliotecas compartidas para inyección 📚.
Persistencia
Linux: Tareas cron ⏰.
Windows: Registro (HKLM\Run) 🔐.
📜 Interpretación del Reporte
INFO: Datos del sistema (no necesariamente vulnerables) ℹ️.
ALERTA: Puntos críticos que debes revisar ASAP 🚨.
Bloques de Código: Detalles técnicos para análisis profundo 📋.
