cat > contar_fallos.py << 'EOF'
#!/usr/bin/env python3
import re
import subprocess
from collections import Counter
from datetime import datetime

def obtener_logs():
    try:
        resultado = subprocess.run(
            ["journalctl", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=30
        )
        return resultado.stdout.splitlines()
    except Exception as e:
        print(f"[ERROR] {e}")
        return []

def extraer_fallos(lineas):
    return [l for l in lineas if "Failed password" in l]

def extraer_ips(lineas_fallos):
    ips = []
    for linea in lineas_fallos:
        match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", linea)
        if match:
            ips.append(match.group(1))
    return ips

def extraer_usuarios(lineas_fallos):
    usuarios = []
    for linea in lineas_fallos:
        match = re.search(r"for\s+(?:invalid user\s+)?(\S+)", linea)
        if match:
            usuarios.append(match.group(1))
    return usuarios

def generar_reporte(lineas_fallos, ips, usuarios):
    total = len(lineas_fallos)
    ips_unicas = Counter(ips)
    usuarios_unicos = Counter(usuarios)
    reporte = []
    reporte.append("=" * 60)
    reporte.append("REPORTE DE ANALISIS DE LOGS - INTENTOS FALLIDOS")
    reporte.append("=" * 60)
    reporte.append(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    reporte.append(f"Fuente: journalctl")
    reporte.append(f"Total de intentos fallidos: {total}")
    reporte.append("")
    if total == 0:
        reporte.append("[OK] No se detectaron intentos fallidos.")
    else:
        reporte.append("TOP 5 IPs ATACANTES:")
        for ip, count in ips_unicas.most_common(5):
            reporte.append(f" {ip}: {count} intentos")
        reporte.append("")
        reporte.append("TOP 5 USUARIOS ATACADOS:")
        for usuario, count in usuarios_unicos.most_common(5):
            reporte.append(f" {usuario}: {count} intentos")
        reporte.append("")
        if total > 100:
            reporte.append("[ALERTA] Severidad ALTA")
        elif total > 20:
            reporte.append("[ALERTA] Severidad MEDIA")
        else:
            reporte.append("[INFO] Severidad BAJA")
    reporte.append("=" * 60)
    for linea in reporte:
        print(linea)
    with open("reporte_fallos.txt", "w") as f:
        f.write("\n".join(reporte))
    print("\n[OK] Reporte guardado en: reporte_fallos.txt")

def main():
    print("[*] Iniciando analisis de logs...")
    lineas = obtener_logs()
    if not lineas:
        print("[INFO] No se pudieron obtener logs.")
        return
    lineas_fallos = extraer_fallos(lineas)
    ips = extraer_ips(lineas_fallos)
    usuarios = extraer_usuarios(lineas_fallos)
    generar_reporte(lineas_fallos, ips, usuarios)

if __name__ == "__main__":
    main()
EOF
