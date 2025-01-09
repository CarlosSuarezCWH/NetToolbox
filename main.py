from fastapi import FastAPI, HTTPException
import whois
from typing import Optional
import ssl
import socket
from fastapi import FastAPI, HTTPException
from typing import Dict
from datetime import datetime
import re
import dns.resolver
import subprocess


app = FastAPI()

# Endpoint para consulta WHOIS
@app.get("/whois")
async def get_whois(domain: str):
    try:
        # Realizar consulta WHOIS
        whois_info = whois.whois(domain)
        
        # Extraer datos clave de la respuesta WHOIS
        if isinstance(whois_info, dict):
            registrant = whois_info.get('registrant', 'No disponible')
            created_on = whois_info.get('creation_date', 'No disponible')
            expires_on = whois_info.get('expiration_date', 'No disponible')
            nameservers = whois_info.get('nameservers', 'No disponible')

            return {
                "domain": domain,
                "registrant": registrant,
                "created_on": created_on,
                "expires_on": expires_on,
                "nameservers": nameservers
            }
        else:
            raise HTTPException(status_code=404, detail="Dominio no encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en la consulta WHOIS: {str(e)}")


# Endpoint para verificar el certificado SSL/TLS
@app.get("/ssl")
async def get_ssl_certificate(url: str):
    try:
        # Convertir la URL a un hostname y puerto
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443  # Puerto HTTPS por defecto

        # Conectar al servidor y obtener el certificado
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.connect((host, port))
        cert = conn.getpeercert()

        # Extraer información relevante del certificado
        issuer = "No disponible"
        if cert.get('issuer'):
            # Buscar la autoridad emisora (commonName)
            for item in cert['issuer']:
                if item[0] == 'commonName':
                    issuer = item[1]
                    break

        not_after = cert.get('notAfter')
        # Convertir la fecha utilizando el formato correcto
        not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")

        # Verificar si el certificado está caducado
        is_valid = not_after > datetime.now()

        return {
            "url": url,
            "valid": is_valid,
            "expires_on": not_after.strftime("%Y-%m-%d %H:%M:%S"),
            "issuer": issuer
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar el certificado SSL: {str(e)}")
    


# Función para verificar si un puerto está abierto
def check_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except (socket.timeout, socket.error):
        return False

# Endpoint para verificar puertos
@app.get("/ports")
async def check_ports(url: str, ports: str):
    try:
        # Limpiar la URL para eliminar caracteres no válidos (como "|")
        host = re.sub(r'[^a-zA-Z0-9.-]', '', url.replace("https://", "").replace("http://", "").split("/")[0])

        # Convertir la lista de puertos recibidos en formato string a una lista de enteros
        ports_list = [int(port) for port in ports.split(",")]

        # Verificar cada puerto
        open_ports = []
        for port in ports_list:
            if check_port(host, port):
                open_ports.append(port)

        return {
            "url": url,
            "open_ports": open_ports
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar los puertos: {str(e)}")
    

# Endpoint para verificar la configuración de DNSSEC
@app.get("/dnssec")
async def check_dnssec(url: str):
    try:
        # Limpiar la URL para obtener solo el dominio
        host = url.replace("https://", "").replace("http://", "").split("/")[0]

        # Crear un resolver DNS y configurar un servidor DNS público
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Usar Google DNS como ejemplo

        dnssec_enabled = False
        
        try:
            # Consultar registros DNSKEY
            dnssec_records = resolver.resolve(host, 'DNSKEY')
            if dnssec_records:
                dnssec_enabled = True
        except dns.resolver.NoAnswer:
            dnssec_enabled = False
        except dns.resolver.NXDOMAIN:
            dnssec_enabled = False
        except dns.resolver.Timeout:
            raise HTTPException(status_code=500, detail="Timeout al consultar DNS")
        except dns.resolver.Servfail:
            raise HTTPException(status_code=500, detail="Servidor DNS falló en la consulta DNSSEC")

        return {
            "url": url,
            "dnssec_enabled": dnssec_enabled
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar DNSSEC: {str(e)}")
    

    # Endpoint para verificar los registros MX
@app.get("/mx")
async def check_mx(url: str):
    try:
        # Limpiar la URL para obtener solo el dominio
        host = url.replace("https://", "").replace("http://", "").split("/")[0]

        # Resolver los registros MX
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Usar Google DNS como ejemplo

        try:
            mx_records = resolver.resolve(host, 'MX')
            mx_details = []

            # Procesar cada registro MX
            for record in mx_records:
                priority = record.preference
                exchange = record.exchange.to_text()

                # Verificar conectividad al servidor SMTP
                is_operational = False
                try:
                    # Intentar conexión al puerto 25
                    with socket.create_connection((exchange, 25), timeout=5):
                        is_operational = True
                except (socket.timeout, socket.error):
                    is_operational = False

                mx_details.append({
                    "priority": priority,
                    "exchange": exchange,
                    "is_operational": is_operational
                })

            return {
                "url": url,
                "mx_records": mx_details
            }

        except dns.resolver.NoAnswer:
            return {"url": url, "mx_records": [], "message": "No se encontraron registros MX"}
        except dns.resolver.NXDOMAIN:
            raise HTTPException(status_code=404, detail="Dominio no encontrado")
        except dns.resolver.Timeout:
            raise HTTPException(status_code=500, detail="Timeout al consultar registros MX")
        except dns.resolver.Servfail:
            raise HTTPException(status_code=500, detail="Error del servidor DNS al consultar registros MX")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar registros MX: {str(e)}")
    

# Endpoint para consultar registros A y AAAA
@app.get("/a_aaaa")
async def check_a_aaaa(url: str):
    try:
        # Limpiar la URL para obtener solo el dominio
        host = url.replace("https://", "").replace("http://", "").split("/")[0]

        # Resolver registros A y AAAA
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Usar Google DNS como ejemplo

        records = {"A": [], "AAAA": []}

        # Consultar registros A
        try:
            a_records = resolver.resolve(host, 'A')
            for record in a_records:
                records["A"].append({
                    "ip": record.address,
                    "ttl": a_records.rrset.ttl
                })
        except dns.resolver.NoAnswer:
            records["A"] = []
        except dns.resolver.NXDOMAIN:
            raise HTTPException(status_code=404, detail="Dominio no encontrado")
        except dns.resolver.Timeout:
            raise HTTPException(status_code=500, detail="Timeout al consultar registros A")

        # Consultar registros AAAA
        try:
            aaaa_records = resolver.resolve(host, 'AAAA')
            for record in aaaa_records:
                records["AAAA"].append({
                    "ip": record.address,
                    "ttl": aaaa_records.rrset.ttl
                })
        except dns.resolver.NoAnswer:
            records["AAAA"] = []
        except dns.resolver.NXDOMAIN:
            raise HTTPException(status_code=404, detail="Dominio no encontrado")
        except dns.resolver.Timeout:
            raise HTTPException(status_code=500, detail="Timeout al consultar registros AAAA")

        return {
            "url": url,
            "records": records
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar registros A/AAAA: {str(e)}")
    

# Endpoint para pruebas de rendimiento de red
@app.get("/network_performance")
async def network_performance(target: str):
    try:
        # Ejecutar comando ping
        process = subprocess.run(
            ["ping", "-c", "4", "-W", "2", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Verificar errores en la ejecución
        if process.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"No se pudo alcanzar el objetivo: {process.stderr.strip()}"
            )

        # Analizar la salida
        output = process.stdout
        latency_lines = [line for line in output.split("\n") if "time=" in line]
        latencies = [float(line.split("time=")[1].split(" ")[0]) for line in latency_lines]

        if not latencies:
            raise HTTPException(status_code=500, detail="No se obtuvieron datos de latencia")

        average_latency = sum(latencies) / len(latencies)

        return {
            "target": target,
            "latency_ms": round(average_latency, 2),
            "status": "reachable"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al realizar pruebas de rendimiento: {str(e)}")
