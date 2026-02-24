# 🛒 ZonaMarket API

> ⚠️ **Este proyecto se encuentra actualmente en desarrollo y no está terminado.**

API REST para la plataforma de marketplace ZonaMarket, construida con PHP 8.2, Slim Framework y MySQL. Gestiona productos, usuarios y órdenes, con soporte de imágenes mediante ImageKit.

---

## 🧰 Tecnologías

- **PHP 8.2** con **Slim Framework**
- **MySQL 8.0**
- **ImageKit** para gestión de imágenes
- **Apache** como servidor web
- **Docker** y **Docker Compose**

---

## 📁 Estructura del proyecto

```
API/
├── public/
│   ├── index.php       # Punto de entrada
│   └── .htaccess
├── src/
│   ├── db.php          # Conexión a base de datos
│   ├── routes.php      # Definición de rutas
│   └── cors.php        # Configuración CORS
├── Slim/
├── vendor/
├── Dockerfile
├── docker-compose.yml
├── apache.conf
└── composer.json
```

---

## 🚀 Despliegue con Docker

### Requisitos

- Docker
- Docker Compose

### 1. Clonar el repositorio

```bash
git clone https://github.com/Mangel-CC/API-MarketPlace.git
cd API-MarketPlace
```

### 2. Configurar variables de entorno

Copia el archivo de ejemplo y completa los valores:

```bash
cp .env.example .env
```

```env
# ImageKit
IMAGEKIT_PUBLIC=tu_public_key
IMAGEKIT_PRIVATE=tu_private_key
IMAGEKIT_URL=https://ik.imagekit.io/tu_id/

# MySQL
MYSQL_HOST=db
MYSQL_ROOT_PASSWORD=tu_password_root
MYSQL_DATABASE=db_tienda
MYSQL_USER=admin
MYSQL_PASSWORD=tu_password
```

### 3. Levantar los contenedores

```bash
docker compose up -d
```

La API estará disponible en `http://localhost:8001`

### 4. Importar la base de datos

Una vez que el contenedor de MySQL esté corriendo, importa el dump:

```bash
docker exec -i market_mysql mysql -u admin -p db_tienda < Backup.sql
```

---

## 📦 Variables de entorno

| Variable | Descripción |
|----------|-------------|
| `IMAGEKIT_PUBLIC` | Clave pública de ImageKit |
| `IMAGEKIT_PRIVATE` | Clave privada de ImageKit |
| `IMAGEKIT_URL` | URL base de ImageKit |
| `MYSQL_HOST` | Host de la base de datos (usar `db` en Docker) |
| `MYSQL_DATABASE` | Nombre de la base de datos |
| `MYSQL_USER` | Usuario de MySQL |
| `MYSQL_PASSWORD` | Contraseña del usuario MySQL |
| `MYSQL_ROOT_PASSWORD` | Contraseña del root de MySQL |

---

## 🔌 Endpoints de la API

### Productos

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/productos` | Listar todos los productos |
| `GET` | `/productos/{id}` | Obtener un producto por ID |
| `POST` | `/productos` | Crear un nuevo producto |
| `PUT` | `/productos/{id}` | Actualizar un producto |
| `DELETE` | `/productos/{id}` | Eliminar un producto |

### Usuarios

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/registro` | Registrar un nuevo usuario |
| `POST` | `/login` | Iniciar sesión |

### Órdenes

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/ordenes` | Listar órdenes |
| `POST` | `/ordenes` | Crear una orden |
| `GET` | `/ordenes/{id}` | Obtener una orden por ID |

> ⚠️ Los endpoints pueden variar según la implementación actual en `src/routes.php`.

---

## 🌐 Despliegue en producción

Este proyecto está configurado para desplegarse automáticamente con [Coolify](https://coolify.io) mediante Docker Compose. Las variables de entorno se configuran directamente en el panel de Coolify.

---

## 📄 Licencia

MIT
