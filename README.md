# RootScope

🌟 PrivAudit - Auditoría Avanzada de Escalada de Privilegios
  

PrivAudit es una herramienta poderosa y avanzada escrita en Bash puro 🚀, diseñada para auditorías de seguridad y pruebas de penetración. Su misión: detectar y explotar vulnerabilidades de escalada de privilegios en sistemas Linux, macOS y Windows (vía WSL, Git Bash o Cygwin). Genera un reporte detallado en PDF 📑 con todas las vulnerabilidades encontradas, perfecto para pentesters, administradores de sistemas y profesionales de ciberseguridad.

⚠️ Advertencia Legal: Usa PrivAudit solo en entornos donde tengas permiso explícito. El uso no autorizado es ilegal y va contra las leyes de seguridad informática.

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
bash
Wrap
Copy
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
🎮 Uso
Ejecución Básica
Corre el script y obtén un reporte completo:

bash
Wrap
Copy
./privaudit.sh
Resultado: Un archivo priv_esc_report_YYYY-MM-DD.pdf con todas las vulnerabilidades 📑.
Si no tienes pandoc, se guarda como .md.
Modo Simulación
Prueba sin ejecutar cambios:

bash
Wrap
Copy
./privaudit.sh --simulate
Ejemplo de Reporte
text
Wrap
Copy
# Reporte Avanzado de Escalada de Privilegios
Fecha: 2025-02-27
Usuario: testuser
Sistema operativo: Linux

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
🤝 Contribuir
¡Únete a la comunidad y haz PrivAudit aún mejor! 🌟

Haz un fork del repositorio.
Crea una rama:
bash
Wrap
Copy
git checkout -b mi-mejora
Commitea tus cambios:
bash
Wrap
Copy
git commit -m "Añadí soporte para X"
Envía un pull request.
Ideas para Contribuir
Nuevos exploits para CVEs recientes 🔥.
Soporte para BSD o sistemas exóticos 🖥️.
Más formatos de reporte (HTML, JSON) 📈.
❓ Preguntas Frecuentes
¿Por qué no genera el PDF?
Instala pandoc y pdflatex. Revisa la sección de instalación 📝.
¿Es seguro ejecutarlo?
Sí con --simulate. Sin esta bandera, modifica el sistema (¡usa con cuidado!) ⚠️.
¿Funciona en Windows nativo?
Necesita WSL, Git Bash o Cygwin para Bash puro 🪟.
📄 Licencia
PrivAudit está bajo la Licencia MIT. Úsalo libremente, pero con responsabilidad.
