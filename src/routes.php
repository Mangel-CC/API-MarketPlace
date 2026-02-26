<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Routing\RouteCollectorProxy;
use ImageKit\ImageKit;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

require __DIR__ . '/./db.php';
require __DIR__ . '/./cors.php';

global $pdo;

/*
|--------------------------------------------------------------------------
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

$app->get('/', function (Request $request, Response $response) {

    $response->getBody()->write(json_encode([
        "status" => "API running OK"
    ]));

    return $response->withHeader('Content-Type', 'application/json');
});

/*
|--------------------------------------------------------------------------
| MIDDLEWARE DE AUTENTICACIÓN
|--------------------------------------------------------------------------
*/
$authMiddleware = function ($request, $handler) use ($pdo) {

    if ($request->getMethod() === 'OPTIONS') {
        $response = new \Slim\Psr7\Response();
        return $response->withStatus(200);
    }

    $authHeader = $request->getHeaderLine('Authorization');

    if (!$authHeader) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode(["error" => "Token requerido"]));
        return $response
            ->withStatus(401)
            ->withHeader('Content-Type', 'application/json');
    }

    $token = str_replace('Bearer ', '', $authHeader);
    $tokenHash = hash('sha256', $token);

    $stmt = $pdo->prepare("
        SELECT usuario_id, fecha_expiracion
        FROM token
        WHERE token_hash = ?
        LIMIT 1
    ");

    $stmt->execute([$tokenHash]);
    $tokenData = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$tokenData) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode(["error" => "Token inválido"]));
        return $response
            ->withStatus(401)
            ->withHeader('Content-Type', 'application/json');
    }

    if (new DateTime($tokenData['fecha_expiracion']) < new DateTime()) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode(["error" => "Token expirado"]));
        return $response
            ->withStatus(401)
            ->withHeader('Content-Type', 'application/json');
    }

    // Guardar usuario en request
    $request = $request->withAttribute('usuario_id', $tokenData['usuario_id']);

    return $handler->handle($request);
};

/*
|--------------------------------------------------------------------------
| GET USER DATA
|--------------------------------------------------------------------------
*/
$app->post('/getUserData', function (Request $request, Response $response) use ($pdo) {

    try {

        $authHeader = $request->getHeaderLine('Authorization');

        if (!$authHeader) {
            $response->getBody()->write(json_encode([
                "success" => false,
                "message" => "Token requerido"
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }

        $rawToken = str_replace('Bearer ', '', $authHeader);
        $tokenHash = hash('sha256', $rawToken);

        $stmt = $pdo->prepare("
            SELECT r.id, r.nombre, r.apellidos, r.email, r.tipo_usuario
            FROM token t
            JOIN registro_usr r ON r.id = t.usuario_id
            WHERE t.token_hash = :token
            LIMIT 1
        ");

        $stmt->execute([
            ':token' => $tokenHash
        ]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $response->getBody()->write(json_encode([
                "success" => false,
                "message" => "Usuario no encontrado"
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }

        $response->getBody()->write(json_encode([
            "success" => true,
            "user" => $user
        ]));

        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {

        error_log("GetUserData error: " . $e->getMessage());

        $response->getBody()->write(json_encode([
            "success" => false
        ]));

        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

});


/*
|--------------------------------------------------------------------------
| GET PROFILE INFO
|--------------------------------------------------------------------------
*/
$app->get('/profile', function (Request $request, Response $response) use ($pdo) {

    $user_id = $request->getAttribute('usuario_id');


    if (!$user_id) {
        $response->getBody()->write(json_encode([
            "error" => "Usuario no autenticado"
        ]));
        return $response->withStatus(401)
            ->withHeader('Content-Type', 'application/json');
    }

    try {
        $stmt = $pdo->prepare("
            SELECT id, nombre, apellidos, email 
            FROM registro_usr 
            WHERE id = ?
        ");
        $stmt->execute([$user_id]);
        $dbUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($dbUser) {
            $response->getBody()->write(json_encode([
                "success" => true,
                "user" => $dbUser
            ]));
            return $response->withHeader('Content-Type', 'application/json');
        }

        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Usuario no encontrado"
        ]));
        return $response->withStatus(404)
            ->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode([
            "error" => "Error BD"
        ]));
        return $response->withStatus(500)
            ->withHeader('Content-Type', 'application/json');
    }

})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| UPDATE PROFILE INFO
|--------------------------------------------------------------------------
*/
$app->post('/profile/update', function (Request $request, Response $response, array $args) use ($pdo) {
    $data = json_decode($request->getBody()->getContents(), true);
    $user_id = $request->getAttribute('usuario_id');

    // Validar que se reciban todos los campos requeridos
    if (
        empty($data['nombre']) ||
        empty($data['apellidos']) ||
        empty($data['email']) ||
        empty($data['password'])
    ) {

        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Faltan campos requeridos"
        ]));
        return $response->withStatus(400);
    }

    $nombre = trim($data['nombre']);
    $apellidos = trim($data['apellidos']);
    $email = trim($data['email']);
    $password = $data['password'];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Email no válido"
        ]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    try {
        // Verificar que la contraseña actual es correcta antes de actualizar
        $stmt = $pdo->prepare("SELECT password FROM registro_usr WHERE id = ?");
        $stmt->execute([$user_id]);
        $currentUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$currentUser || !password_verify($password, $currentUser['password'])) {
            $response->getBody()->write(json_encode([
                "success" => false,
                "message" => "Contraseña incorrecta"
            ]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $stmt = $pdo->prepare("UPDATE registro_usr SET nombre = ?, apellidos = ?, email = ? WHERE id = ?");
        $stmt->execute([$nombre, $apellidos, $email, $user_id]);
        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => "Perfil actualizado correctamente"
        ]));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error al actualizar perfil: " . $e->getMessage());
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Error al actualizar el perfil"
        ]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);


/*
|--------------------------------------------------------------------------
| Validate User Token
|--------------------------------------------------------------------------
*/
$app->post('/validate-token', function (Request $request, Response $response) use ($pdo) {

    try {

        $authHeader = $request->getHeaderLine('Authorization');

        if (!$authHeader) {

            $response->getBody()->write(json_encode([
                "valid" => false
            ]));

            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(401);
        }

        $rawToken = str_replace('Bearer ', '', $authHeader);
        $tokenHash = hash('sha256', $rawToken);

        $stmt = $pdo->prepare("
            SELECT usuario_id, fecha_expiracion
            FROM token
            WHERE token_hash = :token
            LIMIT 1
        ");

        $stmt->execute([':token' => $tokenHash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {

            $response->getBody()->write(json_encode([
                "valid" => false
            ]));

            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(401);
        }

        if (new DateTime($row['fecha_expiracion']) < new DateTime()) {

            $pdo->prepare("DELETE FROM token WHERE token_hash = :token")
                ->execute([':token' => $tokenHash]);

            $response->getBody()->write(json_encode([
                "valid" => false
            ]));

            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(401);
        }

        $response->getBody()->write(json_encode([
            "valid" => true
        ]));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(200);

    } catch (Exception $e) {

        error_log("Error al validar token: " . $e->getMessage());

        $response->getBody()->write(json_encode([
            "valid" => false
        ]));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(500);
    }
});


/*
|--------------------------------------------------------------------------
| GET PRODUCT DETAIL
|--------------------------------------------------------------------------
*/
$app->get('/product/{id}', function (Request $request, Response $response, array $args) use ($pdo) {
    $id = (int) $args['id'];

    // Consulta con JOIN para obtener datos del vendedor
    $sql = "
        SELECT 
            p.id, 
            p.nombre, 
            p.descripcion,
            p.precio,
            p.cantidad,
            p.imagen,
            r.nombre AS vendedor_nombre,
            r.apellidos AS vendedor_apellidos
        FROM productos p
        JOIN registro_usr r ON p.id_vendedor = r.id
        WHERE p.id = :id
    ";

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute(['id' => $id]);
        $producto = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($producto) {
            $response->getBody()->write(json_encode($producto));
            return $response->withStatus(200);
        } else {
            $response->getBody()->write(json_encode(["error" => "Producto no encontrado."]));
            return $response->withStatus(404);
        }
    } catch (PDOException $e) {
        error_log("Error GET /product/{id}: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| GET PRODUCTS
|--------------------------------------------------------------------------
*/
$app->get('/productos', function (Request $request, Response $response) use ($pdo) {
    try {
        $queryParams = $request->getQueryParams();
        $searchQuery = isset($queryParams['search_query']) ? trim($queryParams['search_query']) : '';
        $selectedCategory = isset($queryParams['selected_category']) ? trim($queryParams['selected_category']) : '';

        $sql = "SELECT id, nombre, imagen, CAST(precio AS DECIMAL(10,2)) as precio FROM productos WHERE activo=1";

        if (!empty($searchQuery)) {
            $sql .= " AND nombre LIKE :searchQuery";
        }

        if (!empty($selectedCategory)) {
            $sql .= " AND id_categoria = :selectedCategory";
        }

        $stmt = $pdo->prepare($sql);

        if (!empty($searchQuery)) {
            $stmt->bindValue(':searchQuery', "%$searchQuery%", PDO::PARAM_STR);
        }

        if (!empty($selectedCategory)) {
            $stmt->bindValue(':selectedCategory', $selectedCategory, PDO::PARAM_INT);
        }

        $stmt->execute();
        $productos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode($productos));
    } catch (PDOException $e) {
        error_log("Error GET /productos: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

/*
|--------------------------------------------------------------------------
| GET CATEGORIES
|--------------------------------------------------------------------------
*/
$app->get('/categorias', function (Request $request, Response $response) use ($pdo) {
    try {
        $stmt = $pdo->query("SELECT id, nombre FROM categorias"); // Ajusta la consulta según tu BD
        $categorias = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Enviar directamente la lista, sin envolverla en un objeto JSON
        $response->getBody()->write(json_encode($categorias));
    } catch (PDOException $e) {
        error_log("Error GET /categorias: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/
$app->post('/login', function (Request $request, Response $response) use ($pdo) {

    try {

        $input = json_decode($request->getBody()->getContents(), true);

        if (!$input || empty($input['email']) || empty($input['password'])) {
            $response->getBody()->write(json_encode([
                "error" => "Email y contraseña requeridos"
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        $stmt = $pdo->prepare("
            SELECT id, nombre, email, password 
            FROM registro_usr 
            WHERE email = :email
        ");

        $stmt->execute(['email' => $input['email']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($input['password'], $user['password'])) {
            $response->getBody()->write(json_encode([
                "error" => "Credenciales incorrectas"
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }

        $pdo->prepare("
            DELETE FROM token 
            WHERE usuario_id = :id 
            AND fecha_expiracion < NOW()
        ")->execute(['id' => $user['id']]);


        $rawToken = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);
        $expires = date('Y-m-d H:i:s', strtotime('+30 days'));

        $stmt = $pdo->prepare("
            INSERT INTO token (usuario_id, token_hash, fecha_expiracion)
            VALUES (:id, :token, :expires)
        ");

        $stmt->execute([
            'id' => $user['id'],
            'token' => $tokenHash,
            'expires' => $expires
        ]);

        $response->getBody()->write(json_encode([
            "message" => "Login exitoso",
            "user" => [
                "id" => $user['id'],
                "nombre" => $user['nombre'],
                "email" => $user['email'],
                "token" => $rawToken
            ]
        ]));

        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {

        error_log("Login error: " . $e->getMessage());

        $response->getBody()->write(json_encode([
            "error" => "Error interno"
        ]));

        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

});

/*
|--------------------------------------------------------------------------
| Get My Products
|--------------------------------------------------------------------------
*/
$app->get('/my-products', function (Request $request, Response $response, array $args) use ($pdo) {

    $user_id = $request->getAttribute('usuario_id');

    try {
        $stmt = $pdo->prepare('
            SELECT p.id, p.nombre, p.descripcion, p.precio, p.imagen, p.cantidad, p.id_categoria
            FROM productos p
            INNER JOIN registro_usr r ON p.id_vendedor = r.id
            WHERE r.id = ? AND p.activo = 1
        ');
        $stmt->execute([$user_id]);
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $response->getBody()->write(json_encode($products));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error GET /my-products: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error al obtener productos"]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Delete product
|--------------------------------------------------------------------------
*/
$app->post('/my-products/delete', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    $data = json_decode($request->getBody()->getContents(), true);

    if (empty($data['product_id'])) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Se requiere el product_id"
        ]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }
    $productId = (int) $data['product_id'];

    try {
        // Verificar que el producto pertenece al usuario autenticado
        $stmt = $pdo->prepare("SELECT id FROM productos WHERE id = ? AND id_vendedor = ?");
        $stmt->execute([$productId, $user_id]);
        if (!$stmt->fetch()) {
            $response->getBody()->write(json_encode([
                "success" => false,
                "message" => "Producto no encontrado o no autorizado"
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $stmt = $pdo->prepare("DELETE FROM productos WHERE id = ? AND id_vendedor = ?");
        $stmt->execute([$productId, $user_id]);
        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => "Producto eliminado correctamente"
        ]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        error_log("Error al eliminar producto: " . $e->getMessage());
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Error al eliminar el producto"
        ]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Update product
|--------------------------------------------------------------------------
*/
$app->post('/my-products/update', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    $data = json_decode($request->getBody()->getContents(), true);

    if (empty($data['product_id']) || empty($data['nombre']) || empty($data['descripcion']) ||
        !isset($data['precio']) || !isset($data['cantidad']) || empty($data['id_categoria'])) {
        return jsonResponse($response, [
            "success" => false,
            "message" => "Faltan campos requeridos"
        ], 400);
    }

    if (!is_numeric($data['precio']) || !is_numeric($data['cantidad'])) {
        return jsonResponse($response, [
            "success" => false,
            "error" => "Invalid numeric values"
        ], 400);
    }

    if ((float)$data['precio'] <= 0 || (int)$data['cantidad'] < 1) {
        return jsonResponse($response, [
            "success" => false,
            "error" => "El precio debe ser mayor a 0 y la cantidad al menos 1"
        ], 400);
    }

    try {
        // Verificar que el producto pertenece al usuario
        $stmt = $pdo->prepare("SELECT id FROM productos WHERE id = ? AND id_vendedor = ?");
        $stmt->execute([$data['product_id'], $user_id]);
        if (!$stmt->fetch()) {
            return jsonResponse($response, [
                "success" => false,
                "message" => "Producto no encontrado o no autorizado"
            ], 403);
        }

        $stmt = $pdo->prepare("
            UPDATE productos
            SET nombre = ?, descripcion = ?, precio = ?, cantidad = ?, id_categoria = ?
            WHERE id = ? AND id_vendedor = ?
        ");
        $stmt->execute([
            $data['nombre'],
            $data['descripcion'],
            $data['precio'],
            $data['cantidad'],
            $data['id_categoria'],
            $data['product_id'],
            $user_id
        ]);

        return jsonResponse($response, [
            "success" => true,
            "message" => "Producto actualizado correctamente"
        ]);
    } catch (PDOException $e) {
        error_log("Error POST /my-products/update: " . $e->getMessage());
        return jsonResponse($response, [
            "success" => false,
            "message" => "Error al actualizar el producto"
        ], 500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Register User
|--------------------------------------------------------------------------
*/
$app->post('/register', function (Request $request, Response $response) use ($pdo) {
    try {
        $input = json_decode($request->getBody()->getContents(), true);
        $nombre = $input['name'] ?? '';
        $apellido = $input['lastname'] ?? '';
        $email = $input['email'] ?? '';
        $password = $input['password'] ?? '';


        if (empty($nombre) || empty($apellido) || empty($email) || empty($password)) {
            $response->getBody()->write(json_encode(["success" => false, "message" => "Todos los campos son obligatorios."]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $response->getBody()->write(json_encode(["success" => false, "message" => "Email no válido."]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        if (strlen($password) < 6) {
            $response->getBody()->write(json_encode(["success" => false, "message" => "La contraseña debe tener al menos 6 caracteres."]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }


        $stmt = $pdo->prepare("SELECT id FROM registro_usr WHERE email = :email");
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();

        if ($stmt->fetch()) {
            error_log("El usuario ya está registrado: $email");
            $response->getBody()->write(json_encode(["success" => false, "message" => "El correo ya está registrado."]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(409);
        }


        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);


        $stmt = $pdo->prepare("INSERT INTO registro_usr (nombre, apellidos, email, password) 
                               VALUES (:nombre, :apellido, :email, :password)");


        $stmt->bindParam(':nombre', $nombre, PDO::PARAM_STR);
        $stmt->bindParam(':apellido', $apellido, PDO::PARAM_STR);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':password', $hashedPassword, PDO::PARAM_STR);

        if ($stmt->execute()) {
            $response->getBody()->write(json_encode(["success" => true, "message" => "Usuario registrado correctamente."]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
        } else {
            throw new Exception("No se pudo registrar el usuario.");
        }

    } catch (PDOException $e) {
        error_log("Error en el registro: " . $e->getMessage());
        $response->getBody()->write(json_encode(["success" => false, "message" => "Error en el servidor."]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

/*
|--------------------------------------------------------------------------
| register Review
|--------------------------------------------------------------------------
*/
$app->post('/reviews', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    $data = json_decode($request->getBody()->getContents(), true);

    if (
        empty($data['producto_id']) ||
        !isset($data['comentario']) ||
        !isset($data['calificacion'])
    ) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Faltan datos requeridos"
        ]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    $producto_id = (int) $data['producto_id'];
    $autor_id = $user_id; // Usar el ID del token, no del body
    $comentario = trim($data['comentario']);
    $calificacion = (int) $data['calificacion'];

    // Validar rango de calificación
    if ($calificacion < 1 || $calificacion > 5) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "La calificación debe ser entre 1 y 5"
        ]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    try {
        $stmt = $pdo->prepare("
            INSERT INTO reseñas (producto_id, autor_id, comentario, calificacion)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE comentario = VALUES(comentario), calificacion = VALUES(calificacion)
        ");
        $stmt->execute([$producto_id, $autor_id, $comentario, $calificacion]);
        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => "Reseña registrada exitosamente"
        ]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        error_log("Error al registrar reseña: " . $e->getMessage());
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Error al registrar la reseña"
        ]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Reviews for Product
|--------------------------------------------------------------------------
*/
$app->get('/product/{id}/reviews', function (Request $request, Response $response, array $args) use ($pdo) {
    $product_id = $args['id'];

    try {
        $stmt = $pdo->prepare("
            SELECT r.comentario, r.calificacion, r.fecha, u.nombre AS autor
            FROM `reseñas` r
            JOIN `registro_usr` u ON r.autor_id = u.id
            WHERE r.producto_id = :product_id
            ORDER BY r.fecha DESC
        ");
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->execute();
        $reviews = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($reviews) {
            $response->getBody()->write(json_encode($reviews));
        } else {
            $response->getBody()->write(json_encode(["error" => "No hay reseñas para este producto."]));
        }
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error en /product/{id}/reviews: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error en el servidor"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

/*
|--------------------------------------------------------------------------
| List Products to Review
|--------------------------------------------------------------------------
*/
$app->get('/review-products', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');

    try {
        $stmt = $pdo->prepare('
            SELECT 
                p.id AS producto_id,
                p.nombre,
                p.imagen,
                r.id AS vendedor_id,
                r.nombre AS vendedor
            FROM 
                chat_producto cp
                JOIN productos p ON cp.producto_id = p.id
                JOIN registro_usr r ON p.id_vendedor = r.id
            WHERE 
                cp.usuario_id = ?
        ');
        $stmt->execute([$user_id]);
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $response->getBody()->write(json_encode($products));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error GET /review-products: " . $e->getMessage());
        $response->getBody()->write(json_encode([
            "error" => "Error al obtener productos"
        ]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| ADD TO FAVORITES
|--------------------------------------------------------------------------
*/
$app->post('/favorites/add', function (Request $request, Response $response) use ($pdo) {
    $input = json_decode($request->getBody()->getContents(), true);

    $user_id = $request->getAttribute('usuario_id');
    $product_id = isset($input['product_id']) ? (int) $input['product_id'] : null;

    if (!$user_id || !$product_id) {
        $response->getBody()->write(json_encode(["success" => false, "message" => "Faltan datos"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    try {
        $stmt = $pdo->prepare("SELECT id FROM favoritos WHERE usuario_id = :user_id AND producto_id = :product_id");
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->execute();

        if ($stmt->fetch()) {
            $response->getBody()->write(json_encode(["success" => false, "message" => "El producto ya está en favoritos"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(409);
        }

        $stmt = $pdo->prepare("INSERT INTO favoritos (usuario_id, producto_id) VALUES (:user_id, :product_id)");
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            $response->getBody()->write(json_encode(["success" => true, "message" => "Producto agregado a favoritos"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } else {
            $response->getBody()->write(json_encode(["success" => false, "message" => "No se pudo agregar a favoritos"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }
    } catch (PDOException $e) {
        error_log("Error POST /favorites/add: " . $e->getMessage());
        $response->getBody()->write(json_encode(["success" => false, "error" => "Error en el servidor"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| UPLOAD PRODUCT (IMAGEKIT)
|--------------------------------------------------------------------------
*/
$app->post('/products/upload', function (Request $request, Response $response) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    $files = $request->getUploadedFiles();
    $data = $request->getParsedBody();

    // Validar campos requeridos
    if (
        !isset($files['image']) ||
        !isset($data['nombre']) ||
        !isset($data['descripcion']) ||
        !isset($data['precio']) ||
        !isset($data['id_categoria']) ||
        !isset($data['cantidad'])
    ) {

        return jsonResponse($response, [
            "success" => false,
            "error" => "Missing fields"
        ], 400);
    }

    $image = $files['image'];

    if ($image->getError() !== UPLOAD_ERR_OK) {

        return jsonResponse($response, [
            "success" => false,
            "error" => "Image upload error"
        ], 400);
    }

    $ext = strtolower(pathinfo($image->getClientFilename(), PATHINFO_EXTENSION));

    $allowed = ['jpg', 'jpeg', 'png', 'webp'];

    if (!in_array($ext, $allowed)) {

        return jsonResponse($response, [
            "success" => false,
            "error" => "Invalid file type"
        ], 400);
    }

    // Configurar ImageKit
    $imageKit = new ImageKit(
        getenv('IMAGEKIT_PUBLIC'),
        getenv('IMAGEKIT_PRIVATE'),
        getenv('IMAGEKIT_URL')
    );

    $tmpPath = $image->getFilePath();

    // Subir imagen a ImageKit
    try {
        $upload = $imageKit->upload([
            "file" => fopen($tmpPath, "r"),
            "fileName" => "product_" . uniqid() . "." . $ext,
            "folder" => "/products"
        ]);


        if (!empty($upload->error)) {
            throw new Exception($upload->error->message ?? "Upload failed");
        }

        $imageUrl = $upload->result->url;

    } catch (Exception $e) {
        error_log("Error upload ImageKit: " . $e->getMessage());
        return jsonResponse($response, [
            "success" => false,
            "error" => "Error al subir la imagen"
        ], 500);
    }

    if (!is_numeric($data['precio']) || !is_numeric($data['cantidad'])) {
        return jsonResponse($response, [
            "success" => false,
            "error" => "Invalid numeric values"
        ], 400);
    }

    if ((float)$data['precio'] <= 0 || (int)$data['cantidad'] < 1) {
        return jsonResponse($response, [
            "success" => false,
            "error" => "El precio debe ser mayor a 0 y la cantidad al menos 1"
        ], 400);
    }

    // Insertar datos del producto en la base de datos
    $stmt = $pdo->prepare("
        INSERT INTO productos
        (nombre, descripcion, precio, cantidad, id_vendedor, id_categoria, activo, imagen)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    ");

    $stmt->execute([
        $data['nombre'],
        $data['descripcion'],
        $data['precio'],
        $data['cantidad'],
        $user_id,
        $data['id_categoria'],
        $imageUrl
    ]);

    return jsonResponse($response, [
        "success" => true,
        "url" => $imageUrl
    ], 201);
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Get Favorites
|--------------------------------------------------------------------------
*/
$app->get('/favorites', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    $queryParams = $request->getQueryParams();

    try {
        $stmt = $pdo->prepare('
            SELECT f.id AS favorite_id, p.id AS product_id, p.nombre, p.precio, p.imagen, p.cantidad AS stock
            FROM favoritos f
            INNER JOIN productos p ON f.producto_id = p.id
            INNER JOIN registro_usr r ON f.usuario_id = r.id
            WHERE r.id = :user_id
        ');
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->execute();
        $favorites = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode($favorites));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error GET /favorites: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| CHAT MESSAGES
|--------------------------------------------------------------------------
*/
$app->group('/chat', function (RouteCollectorProxy $group) use ($pdo) {

    $group->get('/{chat_id}/messages', function (Request $request, Response $response, array $args) use ($pdo) {
        $chat_id = (int) $args['chat_id'];

        try {
            $stmt = $pdo->prepare("
                SELECT id, chat_producto_id, usuario_id, producto_id, mensaje, timestamp, vendedor_id
                FROM mensajes
                WHERE chat_producto_id = :chat_id
                ORDER BY timestamp
            ");
            $stmt->bindParam(':chat_id', $chat_id, PDO::PARAM_INT);
            $stmt->execute();
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

            foreach ($messages as &$msg) {
                if (is_resource($msg['mensaje'])) {
                    $msg['mensaje'] = stream_get_contents($msg['mensaje']);
                }
            }

            $payload = json_encode(["success" => true, "messages" => $messages]);
            $response->getBody()->write($payload);
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } catch (PDOException $e) {
            error_log("Error GET /chat/{id}/messages: " . $e->getMessage());
            $payload = json_encode(["success" => false, "error" => "Error en el servidor"]);
            $response->getBody()->write($payload);
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }
    });

    $group->post('/{chat_id}/newMessage', function (Request $request, Response $response, array $args) use ($pdo) {
        $chat_id = (int) $args['chat_id'];
        $input = json_decode($request->getBody()->getContents(), true);

        $user_id = isset($input['user_id']) ? (int) $input['user_id'] : null;
        $product_id = isset($input['product_id']) ? (int) $input['product_id'] : null;
        $mensaje = isset($input['mensaje']) ? trim($input['mensaje']) : null;
        $vendedor_id = isset($input['vendedor_id']) ? (int) $input['vendedor_id'] : null;
        $buyer_id = isset($input['buyer_id']) ? (int) $input['buyer_id'] : null;

        if (!$user_id || !$product_id || !$mensaje || !$vendedor_id || ($user_id == $vendedor_id && !$buyer_id)) {
            $response->getBody()->write(json_encode(["success" => false, "error" => "Faltan datos"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        $receptor_id = ($user_id == $vendedor_id) ? $buyer_id : $vendedor_id;

        try {
            $stmt = $pdo->prepare("
                INSERT INTO mensajes (chat_producto_id, usuario_id, producto_id, mensaje, vendedor_id, timestamp)
                VALUES (:chat_id, :user_id, :product_id, :mensaje, :vendedor_id, CONVERT_TZ(NOW(), 'UTC', 'America/Mexico_City'))
            ");
            $stmt->bindParam(':chat_id', $chat_id, PDO::PARAM_INT);
            $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
            $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
            $stmt->bindParam(':mensaje', $mensaje, PDO::PARAM_STR);
            $stmt->bindParam(':vendedor_id', $vendedor_id, PDO::PARAM_INT);

            if ($stmt->execute()) {
                $stmt = $pdo->prepare("
                INSERT INTO notificaciones (usuario_id, mensaje)
                VALUES (:receptor_id, 'Tienes un nuevo mensaje en el chat del producto.')
            ");
                $stmt->bindParam(':receptor_id', $receptor_id, PDO::PARAM_INT);
                $stmt->execute();

                $payload = json_encode(["success" => true, "message" => "Mensaje enviado"]);
                $response->getBody()->write($payload);
                return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
            } else {
                $payload = json_encode(["success" => false, "error" => "No se pudo enviar el mensaje"]);
                $response->getBody()->write($payload);
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
            }
        } catch (PDOException $e) {
            error_log("Error POST /chat/{id}/newMessage: " . $e->getMessage());
            $payload = json_encode(["success" => false, "error" => "Error en el servidor"]);
            $response->getBody()->write($payload);
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }
    });

})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| CREATE CHAT
|--------------------------------------------------------------------------
*/
$app->post('/chat/start', function (Request $request, Response $response) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id'); // Usar ID del token
    $input = json_decode($request->getBody()->getContents(), true);
    $product_id = isset($input['product_id']) ? (int) $input['product_id'] : null;

    if (!$product_id) {
        $response->getBody()->write(json_encode(["error" => "product_id es requerido"]));
        return $response->withHeader('Content-Type', 'application/json')
            ->withStatus(400);
    }

    try {
        $stmt = $pdo->prepare("SELECT id_vendedor FROM productos WHERE id = :product_id");
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->execute();
        $vendedor = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$vendedor) {
            error_log("Error: Producto no encontrado");
            $response->getBody()->write(json_encode(["error" => "Producto no encontrado"]));
            return $response->withHeader('Content-Type', 'application/json')
                ->withStatus(404);
        }

        $vendedor_id = $vendedor['id_vendedor'];
        error_log("Vendedor encontrado: $vendedor_id");


        $stmt = $pdo->prepare("SELECT id FROM chat_producto WHERE producto_id = :product_id AND usuario_id = :user_id");
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->execute();
        $chat = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($chat) {
            error_log("Chat ya existente: ID = " . $chat['id']);
            $response->getBody()->write(json_encode([
                "chat_id" => $chat['id'],
                "vendedor_id" => $vendedor_id
            ]));
            return $response->withHeader('Content-Type', 'application/json')
                ->withStatus(200);
        }


        error_log("🆕 Creando chat...");
        $stmt = $pdo->prepare("INSERT INTO chat_producto (usuario_id, producto_id, vendedor_id) VALUES (:user_id, :product_id, :vendedor_id)");
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->bindParam(':vendedor_id', $vendedor_id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            $chat_id = $pdo->lastInsertId();
            error_log("Chat creado con éxito: ID = $chat_id");
            $response->getBody()->write(json_encode([
                "chat_id" => $chat_id,
                "vendedor_id" => $vendedor_id
            ]));
            return $response->withHeader('Content-Type', 'application/json')
                ->withStatus(201);
        } else {
            error_log(" Error: No se pudo crear el chat");
            $response->getBody()->write(json_encode(["error" => "No se pudo iniciar el chat"]));
            return $response->withHeader('Content-Type', 'application/json')
                ->withStatus(500);
        }
    } catch (PDOException $e) {
        error_log("Error en el servidor: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error en el servidor"]));
        return $response->withHeader('Content-Type', 'application/json')
            ->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| GET CHAT LIST
|--------------------------------------------------------------------------
*/
$app->get('/chat/list', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    error_log("user_id recibido: " . $user_id);
    try {
        $stmt = $pdo->prepare('
            SELECT 
                cp.id AS chat_id, 
                p.id AS producto_id, 
                p.nombre AS producto_nombre, 
                p.imagen AS imagen, 
                r1.id AS usuario_id, 
                IF(r1.id = :user_id, "tu", r1.nombre) AS comprador, 
                r2.id AS vendedor_id, 
                IF(r2.id = :user_id, "tu", r2.nombre) AS vendedor
            FROM 
                chat_producto cp
                JOIN productos p ON cp.producto_id = p.id
                JOIN registro_usr r1 ON cp.usuario_id = r1.id
                JOIN registro_usr r2 ON cp.vendedor_id = r2.id
            WHERE 
                cp.usuario_id = :user_id OR cp.vendedor_id = :user_id
        ');
        $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
        $stmt->execute();
        $chats = $stmt->fetchAll(PDO::FETCH_ASSOC);


        $response->getBody()->write(json_encode($chats));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error GET /chat/list: " . $e->getMessage());
        $error = ["error" => "Error al obtener chats"];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);;

/*
|--------------------------------------------------------------------------
| GET UNREAD NOTIFICATIONS COUNT
|--------------------------------------------------------------------------
*/
$app->get('/notifications/count', function (Request $request, Response $response) use ($pdo) {  
    $user_id = $request->getAttribute('usuario_id');

    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) AS count FROM notificaciones WHERE usuario_id = ? AND leida = 0");
        $stmt->execute([$user_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        $data = ["unreadCount" => (int) $result['count']];
        $response->getBody()->write(json_encode($data));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error GET /notifications/count: " . $e->getMessage());
        $data = ["error" => "Error al obtener notificaciones"];
        $response->getBody()->write(json_encode($data));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| GET NOTIFICATIONS
|--------------------------------------------------------------------------
*/
$app->get('/notifications', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');

    try {
        $stmt = $pdo->prepare("SELECT * FROM notificaciones WHERE usuario_id = ? ORDER BY fecha DESC");
        $stmt->execute([$user_id]);
        $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $response->getBody()->write(json_encode($notifications));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        error_log("Error GET /notifications: " . $e->getMessage());
        $response->getBody()->write(json_encode([
            "error" => "Error interno"
        ]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Mark Notifications as Readed
|--------------------------------------------------------------------------
*/
$app->post('/notifications/mark-read', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');

    try {
        $stmt = $pdo->prepare("UPDATE notificaciones SET leida = 1 WHERE usuario_id = ? AND leida = 0");
        $stmt->execute([$user_id]);
        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => "Notificaciones marcadas como leídas"
        ]));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Error interno"
        ]));
        return $response->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Delete All Notifications
|--------------------------------------------------------------------------
*/
$app->post('/notifications/delete-all', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    
    try {
        $stmt = $pdo->prepare("DELETE FROM notificaciones WHERE usuario_id = ?");
        $stmt->execute([$user_id]);
        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => "Todas las notificaciones eliminadas"
        ]));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Error interno"
        ]));
        return $response->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Delete Single Notification
|--------------------------------------------------------------------------
*/
$app->post('/notifications/delete', function (Request $request, Response $response, array $args) use ($pdo) {
    $user_id = $request->getAttribute('usuario_id');
    $data = json_decode($request->getBody()->getContents(), true);

    if (empty($data['id'])) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Se requiere el id de la notificación"
        ]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    $id = (int) $data['id'];

    try {
        // Solo eliminar si la notificación pertenece al usuario autenticado
        $stmt = $pdo->prepare("DELETE FROM notificaciones WHERE id = ? AND usuario_id = ?");
        $stmt->execute([$id, $user_id]);
        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => "Notificación eliminada"
        ]));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode([
            "success" => false,
            "message" => "Error interno"
        ]));
        return $response->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| CARRITO - Obtener carrito del usuario
| GET /cart
|--------------------------------------------------------------------------
*/
$app->get('/cart', function (Request $request, Response $response) use ($pdo) {
    try {
        $usuario_id = $request->getAttribute('usuario_id');

        // Obtener o crear carrito
        $stmt = $pdo->prepare("SELECT id FROM carrito WHERE usuario_id = :usuario_id");
        $stmt->execute(['usuario_id' => $usuario_id]);
        $carrito = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$carrito) {
            $response->getBody()->write(json_encode(["carrito_id" => null, "items" => [], "total" => 0]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        }

        // Obtener items con detalle del producto
        $stmt = $pdo->prepare("
            SELECT 
                ci.id AS item_id,
                ci.cantidad,
                p.id AS producto_id,
                p.nombre,
                p.precio,
                p.imagen,
                (p.precio * ci.cantidad) AS subtotal
            FROM carrito_items ci
            JOIN productos p ON p.id = ci.producto_id
            WHERE ci.carrito_id = :carrito_id
        ");
        $stmt->execute(['carrito_id' => $carrito['id']]);
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $total = array_sum(array_column($items, 'subtotal'));

        $response->getBody()->write(json_encode([
            "carrito_id" => $carrito['id'],
            "items" => $items,
            "total" => $total
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {
        error_log("Error GET /cart: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| CART - Add item
|--------------------------------------------------------------------------
*/
$app->post('/cart/add', function (Request $request, Response $response) use ($pdo) {
    try {
        $usuario_id = $request->getAttribute('usuario_id');
        $input = json_decode($request->getBody()->getContents(), true);
        $producto_id = isset($input['producto_id']) ? (int) $input['producto_id'] : null;
        $cantidad = isset($input['cantidad']) ? (int) $input['cantidad'] : 1;

        if (!$producto_id || $cantidad < 1) {
            $response->getBody()->write(json_encode(["error" => "producto_id y cantidad válida son requeridos"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        // Verificar que el producto existe y tiene stock
        $stmt = $pdo->prepare("SELECT id, cantidad FROM productos WHERE id = :id AND activo = 1");
        $stmt->execute(['id' => $producto_id]);
        $producto = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$producto) {
            $response->getBody()->write(json_encode(["error" => "Producto no encontrado"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(404);
        }

        if ($producto['cantidad'] < $cantidad) {
            $response->getBody()->write(json_encode(["error" => "Stock insuficiente"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(409);
        }

        // Obtener o crear carrito
        $stmt = $pdo->prepare("SELECT id FROM carrito WHERE usuario_id = :usuario_id");
        $stmt->execute(['usuario_id' => $usuario_id]);
        $carrito = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$carrito) {
            $stmt = $pdo->prepare("INSERT INTO carrito (usuario_id) VALUES (:usuario_id)");
            $stmt->execute(['usuario_id' => $usuario_id]);
            $carrito_id = $pdo->lastInsertId();
        } else {
            $carrito_id = $carrito['id'];
        }

        // Si el producto ya está en el carrito, sumar cantidad
        $stmt = $pdo->prepare("SELECT id, cantidad FROM carrito_items WHERE carrito_id = :carrito_id AND producto_id = :producto_id");
        $stmt->execute(['carrito_id' => $carrito_id, 'producto_id' => $producto_id]);
        $item_existente = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($item_existente) {
            $nueva_cantidad = $item_existente['cantidad'] + $cantidad;
            $stmt = $pdo->prepare("UPDATE carrito_items SET cantidad = :cantidad WHERE id = :id");
            $stmt->execute(['cantidad' => $nueva_cantidad, 'id' => $item_existente['id']]);
        } else {
            $stmt = $pdo->prepare("INSERT INTO carrito_items (carrito_id, producto_id, cantidad) VALUES (:carrito_id, :producto_id, :cantidad)");
            $stmt->execute(['carrito_id' => $carrito_id, 'producto_id' => $producto_id, 'cantidad' => $cantidad]);
        }

        $response->getBody()->write(json_encode(["success" => true, "message" => "Producto agregado al carrito"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {
        error_log("Error POST /cart/add: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| CART - Remove a single item
|--------------------------------------------------------------------------
*/
$app->delete('/cart/remove', function (Request $request, Response $response) use ($pdo) {
    try {
        $usuario_id = $request->getAttribute('usuario_id');
        $input = json_decode($request->getBody()->getContents(), true);
        $item_id = isset($input['item_id']) ? (int) $input['item_id'] : null;

        if (!$item_id) {
            $response->getBody()->write(json_encode(["error" => "item_id es requerido"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        // Verificar que el item pertenece al carrito del usuario
        $stmt = $pdo->prepare("
            SELECT ci.id FROM carrito_items ci
            JOIN carrito c ON c.id = ci.carrito_id
            WHERE ci.id = :item_id AND c.usuario_id = :usuario_id
        ");
        $stmt->execute(['item_id' => $item_id, 'usuario_id' => $usuario_id]);

        if (!$stmt->fetch()) {
            $response->getBody()->write(json_encode(["error" => "Item no encontrado"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(404);
        }

        $stmt = $pdo->prepare("DELETE FROM carrito_items WHERE id = :id");
        $stmt->execute(['id' => $item_id]);

        $response->getBody()->write(json_encode(["success" => true, "message" => "Producto eliminado del carrito"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {
        error_log("Error DELETE /cart/remove: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| CART - Clear all cart items
|--------------------------------------------------------------------------
*/
$app->post('/cart/clear', function (Request $request, Response $response) use ($pdo) {
    try {
        $usuario_id = $request->getAttribute('usuario_id');

        $stmt = $pdo->prepare("
            DELETE ci FROM carrito_items ci
            JOIN carrito c ON c.id = ci.carrito_id
            WHERE c.usuario_id = :usuario_id
        ");
        $stmt->execute(['usuario_id' => $usuario_id]);

        $response->getBody()->write(json_encode(["success" => true, "message" => "Carrito vaciado"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {
        error_log("Error DELETE /cart/clear: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| FAVORITES - Toggle (Add/Remove) a product from favorites
|--------------------------------------------------------------------------
*/
$app->post('/favorites/toggle', function (Request $request, Response $response) use ($pdo) {
    try {
        $usuario_id = $request->getAttribute('usuario_id');
        $input = json_decode($request->getBody()->getContents(), true);
        $producto_id = isset($input['producto_id']) ? (int) $input['producto_id'] : null;

        if (!$producto_id) {
            $response->getBody()->write(json_encode(["error" => "producto_id es requerido"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        $stmt = $pdo->prepare("
            SELECT id FROM favoritos 
            WHERE usuario_id = :usuario_id AND producto_id = :producto_id
        ");
        $stmt->execute(['usuario_id' => $usuario_id, 'producto_id' => $producto_id]);
        $existente = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existente) {
            $stmt = $pdo->prepare("DELETE FROM favoritos WHERE id = :id");
            $stmt->execute(['id' => $existente['id']]);
            $message = "Eliminado de favoritos";
            $is_favorito = false;
        } else {
            $stmt = $pdo->prepare("INSERT INTO favoritos (usuario_id, producto_id) VALUES (:usuario_id, :producto_id)");
            $stmt->execute(['usuario_id' => $usuario_id, 'producto_id' => $producto_id]);
            $message = "Agregado a favoritos";
            $is_favorito = true;
        }

        $response->getBody()->write(json_encode([
            "success" => true,
            "message" => $message,
            "is_favorito" => $is_favorito
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {
        error_log("Error POST /favorites/toggle: " . $e->getMessage());
        $response->getBody()->write(json_encode(["error" => "Error interno"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Orders - Get all orders for authenticated user
|--------------------------------------------------------------------------
*/
$app->get('/orders', function (Request $request, Response $response) use ($pdo) {
    $usuario_id = $request->getAttribute('usuario_id');

    try {
        $stmt = $pdo->prepare("
            SELECT 
                o.id,
                o.producto_id,
                p.nombre AS producto_nombre,
                p.imagen AS producto_imagen,
                o.cantidad,
                o.precio_unitario,
                o.total,
                o.estado,
                o.direccion_envio,
                o.fecha_creacion
            FROM ordenes o
            JOIN productos p ON p.id = o.producto_id
            WHERE o.usuario_id = :usuario_id
            ORDER BY o.fecha_creacion DESC
        ");
        $stmt->execute(['usuario_id' => $usuario_id]);
        $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return jsonResponse($response, ["success" => true, "orders" => $orders]);

    } catch (Exception $e) {
        error_log("Error GET /orders: " . $e->getMessage());
        return jsonResponse($response, ["error" => "Error interno"], 500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Orders - Get order details
|--------------------------------------------------------------------------
*/
$app->get('/orders/{id}', function (Request $request, Response $response, array $args) use ($pdo) {
    $usuario_id = $request->getAttribute('usuario_id');
    $orden_id = (int) $args['id'];

    try {
        $stmt = $pdo->prepare("
            SELECT 
                o.id,
                o.producto_id,
                p.nombre AS producto_nombre,
                p.imagen AS producto_imagen,
                p.descripcion AS producto_descripcion,
                o.cantidad,
                o.precio_unitario,
                o.total,
                o.estado,
                o.direccion_envio,
                o.fecha_creacion
            FROM ordenes o
            JOIN productos p ON p.id = o.producto_id
            WHERE o.id = :orden_id AND o.usuario_id = :usuario_id
        ");
        $stmt->execute(['orden_id' => $orden_id, 'usuario_id' => $usuario_id]);
        $order = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$order) {
            return jsonResponse($response, ["error" => "Orden no encontrada"], 404);
        }

        return jsonResponse($response, ["success" => true, "order" => $order]);

    } catch (Exception $e) {
        error_log("Error GET /orders/{id}: " . $e->getMessage());
        return jsonResponse($response, ["error" => "Error interno"], 500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Orders - Create new order
|--------------------------------------------------------------------------
*/
$app->post('/orders/create', function (Request $request, Response $response) use ($pdo) {
    $usuario_id = $request->getAttribute('usuario_id');
    $input = json_decode($request->getBody()->getContents(), true);

    $producto_id = $input['producto_id'] ?? null;
    $cantidad = $input['cantidad'] ?? 1;
    $direccion_envio = $input['direccion_envio'] ?? null;

    if (!$producto_id || $cantidad < 1) {
        return jsonResponse($response, ["error" => "producto_id y cantidad son requeridos"], 400);
    }

    try {
        $stmt = $pdo->prepare("SELECT id, precio, cantidad FROM productos WHERE id = :id AND activo = 1");
        $stmt->execute(['id' => $producto_id]);
        $producto = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$producto) {
            return jsonResponse($response, ["error" => "Producto no encontrado o inactivo"], 404);
        }

        if ($producto['cantidad'] < $cantidad) {
            return jsonResponse($response, ["error" => "Stock insuficiente"], 409);
        }

        $precio_unitario = $producto['precio'];
        $total = $precio_unitario * $cantidad;

        $stmt = $pdo->prepare("
            INSERT INTO ordenes (usuario_id, producto_id, cantidad, precio_unitario, total, direccion_envio)
            VALUES (:usuario_id, :producto_id, :cantidad, :precio_unitario, :total, :direccion_envio)
        ");
        $stmt->execute([
            'usuario_id'      => $usuario_id,
            'producto_id'     => $producto_id,
            'cantidad'        => $cantidad,
            'precio_unitario' => $precio_unitario,
            'total'           => $total,
            'direccion_envio' => $direccion_envio,
        ]);

        $orden_id = $pdo->lastInsertId();

        // Descontar stock
        $pdo->prepare("UPDATE productos SET cantidad = cantidad - :cantidad WHERE id = :id")
            ->execute(['cantidad' => $cantidad, 'id' => $producto_id]);

        return jsonResponse($response, [
            "success"  => true,
            "message"  => "Orden creada exitosamente",
            "orden_id" => $orden_id,
            "total"    => $total
        ], 201);

    } catch (Exception $e) {
        error_log("Error POST /orders/create: " . $e->getMessage());
        return jsonResponse($response, ["error" => "Error interno"], 500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| Orders - Cancel order
|--------------------------------------------------------------------------
*/
$app->put('/orders/{id}/cancel', function (Request $request, Response $response, array $args) use ($pdo) {
    $usuario_id = $request->getAttribute('usuario_id');
    $orden_id = (int) $args['id'];

    try {
        $stmt = $pdo->prepare("
            SELECT id, estado, producto_id, cantidad 
            FROM ordenes 
            WHERE id = :orden_id AND usuario_id = :usuario_id
        ");
        $stmt->execute(['orden_id' => $orden_id, 'usuario_id' => $usuario_id]);
        $orden = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$orden) {
            return jsonResponse($response, ["error" => "Orden no encontrada"], 404);
        }

        if (!in_array($orden['estado'], ['pendiente', 'confirmado'])) {
            return jsonResponse($response, [
                "error" => "No se puede cancelar una orden en estado: " . $orden['estado']
            ], 409);
        }

        $pdo->prepare("UPDATE ordenes SET estado = 'cancelado' WHERE id = :id")
            ->execute(['id' => $orden_id]);

        // Restaurar stock
        $pdo->prepare("UPDATE productos SET cantidad = cantidad + :cantidad WHERE id = :id")
            ->execute(['cantidad' => $orden['cantidad'], 'id' => $orden['producto_id']]);

        return jsonResponse($response, ["success" => true, "message" => "Orden cancelada exitosamente"]);

    } catch (Exception $e) {
        error_log("Error PUT /orders/{id}/cancel: " . $e->getMessage());
        return jsonResponse($response, ["error" => "Error interno"], 500);
    }
})->add($authMiddleware);

/*
|--------------------------------------------------------------------------
| JSON HELPER
|--------------------------------------------------------------------------
*/

function jsonResponse(Response $response, $data, $code = 200)
{
    $response->getBody()->write(json_encode($data));
    return $response
        ->withStatus($code)
        ->withHeader('Content-Type', 'application/json');
}
