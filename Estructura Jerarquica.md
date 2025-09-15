1. Reconocimiento y Enumeración
   ├── 1.1. Enumeración Básica de Dominio
   ├── 1.2. Enumeración de Usuarios
   ├── 1.3. Enumeración de Grupos
   ├── 1.4. Enumeración de Computadoras
   ├── 1.5. Enumeración de Políticas (GPO)
   ├── 1.6. Escaneo de Puertos y Servicios
   ├── 1.7. Búsqueda de Shares SMB
   ├── 1.8. Enumeración de Relaciones de Confianza
   └── 1.9. Contraseñas en Comentarios de Usuarios

2. Escalada de Privilegios y Credenciales
   ├── 2.1. Kerberoasting
   ├── 2.2. AS-REP Roasting
   ├── 2.3. Password Spraying
   ├── 2.4. Pass-the-Hash
   ├── 2.5. OverPass-the-Hash
   ├── 2.6. MS14-068
   ├── 2.7. Abuso de Grupos Peligrosos
   ├── 2.8. Contraseñas en GPP
   ├── 2.9. Abuso de contraseñas LAPS
   ├── 2.10. Shadow Credentials
   ├── 2.11. NoPac Exploitation
   ├── 2.12. AD CS Attacks
   └── 2.13. DACL Abuse

3. Movimiento Lateral
   ├── 3.1. WMI Execution
   ├── 3.2. PSRemoting / WinRM
   ├── 3.3. Scheduled Tasks
   ├── 3.4. Creación de Servicios
   ├── 3.5. Pass-the-Hash
   └── 3.6. Pass-the-Ticket
        ├── 3.6.1. Golden Ticket
        ├── 3.6.2. Silver Ticket
        └── 3.6.3. Trust Ticket

4. Persistencia
   ├── 4.1. Golden Ticket
   ├── 4.2. Silver Ticket
   ├── 4.3. DSRM Password
   ├── 4.4. Skeleton Key
   └── 4.5. AdminSDHolder

5. Extracción de Datos
   ├── 5.1. NTDS.dit Extraction
   ├── 5.2. Group Policy Preferences (GPP)
   ├── 5.3. LAPS Passwords
   └── 5.4. Volume Shadow Copy (VSS)

6. Herramientas y Comandos Útiles
   ├── 6.1. Impacket Suite
   ├── 6.2. CrackMapExec
   ├── 6.3. Kerbrute
   ├── 6.4. Mimikatz
   ├── 6.5. Rubeus
   └── 6.6. PowerSploit

7. Técnicas de Evasión
   ├── 7.1. Ofuscación de Scripts (PowerShell)
   ├── 7.2. AMSI Bypass
   ├── 7.3. AppLocker Bypass
   └── 7.4. Constrained Language Mode Bypass

8. Ataques de Exchange
   ├── 8.1. PrivExchange Attack
   ├── 8.2. CVE-2020-0688
   ├── 8.3. CVE-2018-8581
   └── 8.4. Enumeración de Exchange

9. Ataques de Relaying
   ├── 9.1. NTLMv2 Relaying (General)
   ├── 9.2. Mitm6 + ntlmrelayx (IPv6)
   ├── 9.3. Configuración de Responder
   ├── 9.4. Relay a LDAP/S
   └── 9.5. Relay a SMB

10. Herramientas de Assessment
    ├── 10.1. Ping Castle
    ├── 10.2. BloodHound
    ├── 10.3. ADAPE Script
    ├── 10.4. Ranger
    ├── 10.5. AdExplorer (Sysinternals)
    └── 10.6. PowerSploit

11. Métodos de Ejecución y Descarga
    ├── 11.1. Descarga y Ejecución desde Web
    ├── 11.2. Ejecución con PowerShell
    ├── 11.3. Ejecución con Binarios de Windows
    └── 11.4. Técnicas de Ofuscación

12. Herramientas de Comando y Control
    ├── 12.1. Koadic C3
    ├── 12.2. Covenant
    ├── 12.3. Sliver
    ├── 12.4. Metasploit
    └── 12.5. Cobalt Strike

13. Ataques a AD CS (PKI)
    ├── 13.1. Enumeración de AD CS
    ├── 13.2. ESC1 - Misconfiguración de Plantillas
    ├── 13.3. ESC3 - Enrolamiento de Agentes
    ├── 13.4. ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
    ├── 13.5. ESC8 - ADCSPWN (Relaying to AD CS)
    ├── 13.6. ESC9 - No Requiere Filtrar
    └── 13.7. ESC10 - Weak Certificate Mappings

14. Shadow Credentials
    ├── 14.1. Enumeración de msDS-KeyCredentialLink
    ├── 14.2. PyWhisker Attack
    ├── 14.3. PKINITtools Exploitation
    └── 14.4. Limpieza de Shadow Credentials

15. NoPac (SamAccountName Spoofing)
    ├── 15.1. Detección de Vulnerabilidad
    ├── 15.2. NoPac.py Exploitation
    ├── 15.3. CrackMapExec Module
    └── 15.4. Mitigaciones y Detección

16. Delegación de Kerberos
    ├── 16.1. Enumeración de Delegación
    ├── 16.2. Unconstrained Delegation
    ├── 16.3. Constrained Delegation
    └── 16.4. Resource-Based Constrained Delegation

17. Ataques a MSSQL y SCCM
    ├── 17.1. Enumeración de MSSQL
    ├── 17.2. MSSQL Trusted Links
    ├── 17.3. SCCM Infrastructure Discovery
    ├── 17.4. SCCM Primary Users
    └── 17.5. SCCM Hunter

18. Abuso de DACLs
    ├── 18.1. Enumeración de DACLs
    ├── 18.2. GenericAll/GenericWrite
    ├── 18.3. WriteProperty Attacks
    ├── 18.4. ResetPassword/ForceChangePassword
    ├── 18.5. AddMember Attacks
    └── 18.6. WriteOwner Attacks

19. Configuración de Entorno
    ├── 19.1. Configurar Dominio
    ├── 19.2. Configurar DC IP
    ├── 19.3. Configurar Usuario
    ├── 19.4. Configurar Contraseña
    ├── 19.5. Configurar Hash NTLM
    ├── 19.6. Configurar IP Objetivo
    └── 19.7. Configurar CA Server
