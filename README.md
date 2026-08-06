Requirements:
- ubuntu server 24.04.3

## 1. Instalación

```bash
# 1. Clone the repository
# 1. Clona el repositorio
git clone https://github.com/AndryHalcons/Praesidium_Firewall.git

# 2. Enter the installer directory
# 2. Entra al directorio del instalador
cd Praesidium_Firewall/installation

# 3. Give execution permissions to the installer
# 3. Da permisos de ejecución al instalador
sudo chmod +x installer.sh

# 4. Run the installer
# 4. Ejecuta el instalador
sudo ./installer.sh
```
## 2. Login
default user: praesidium  
default pass: praesidium  
![Login screen](git_assets/praesidium_login.png)

## Notes

After installation, replace `<management-ip>` with the management IP address assigned to the Praesidium host.

| Service | URL |
| --- | --- |
| FastAPI documentation | `http://<management-ip>:8000/docs#/` |
| Web interface | `https://<management-ip>` |
