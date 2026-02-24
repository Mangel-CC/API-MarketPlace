<?php

use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();
$errorMiddleware = $app->addErrorMiddleware(true, true, true);

// JSON middleware
$app->addBodyParsingMiddleware();

// CORS
require __DIR__ . '/../src/cors.php';

// Routes
require __DIR__ . '/../src/routes.php';

require __DIR__ . '/../src/db.php';

$app->get('/db-test', function ($request, $response) use ($pdo) {

    $stmt = $pdo->query("SHOW TABLES");
    $tables = $stmt->fetchAll();

    $response->getBody()->write(json_encode($tables));
    return $response->withHeader('Content-Type', 'application/json');

});


$app->run();
