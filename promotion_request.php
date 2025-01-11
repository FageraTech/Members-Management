<?php
session_start();
include 'db.php';

// Generate CSRF token if not already set
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle promotion request submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['error_message'] = 'Invalid CSRF token. Please try again.';
        header('Location: promotion_request.php');
        exit();
    }

    // Get user details
    $user_id = $_SESSION['user_id']; // Assume user ID is stored in session
    $request_date = date('Y-m-d H:i:s');

    // Insert promotion request into database
    $stmt = $conn->prepare("INSERT INTO promotion_requests (user_id, request_date) VALUES (?, ?)");
    $stmt->bind_param("is", $user_id, $request_date);

    if ($stmt->execute()) {
        $_SESSION['success_message'] = 'Your request for promotion has been submitted.';
        header('Location: Member_dashboard.php');
        exit();
    } else {
        $_SESSION['error_message'] = 'Error: ' . $conn->error;
        header('Location: promotion_request.php');
        exit();
    }
}

$stmt->close();
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Promotion Request</title>
    <!-- Bootstrap CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #e8f5e9; /* Light green background */
            color: #333; /* Dark gray text color */
        }
        .container {
            background-color: #ffffff; /* White container */
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            margin-top: 50px;
        }
        h1, h2 {
            color: #2e7d32; /* Dark green color for headers */
        }
        .btn-primary {
            background-color: #388e3c; /* Green button */
            border-color: #388e3c;
        }
        .btn-primary:hover {
            background-color: #2e7d32; /* Darker green on hover */
            border-color: #2e7d32;
        }
        .error {
            color: #d32f2f;
            margin-top: 10px;
        }
        .success {
            color: #388e3c;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mt-4">Promotion Request</h1>
        <p>Submit your request for admin promotion here.</p>
        <?php if (isset($_SESSION['error_message'])): ?>
            <div class="alert alert-danger" access_level="alert">
                <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?>
            </div>
        <?php endif; ?>
        <?php if (isset($_SESSION['success_message'])): ?>
            <div class="alert alert-success" access_level="alert">
                <?php echo $_SESSION['success_message']; unset($_SESSION['success_message']); ?>
            </div>
        <?php endif; ?>
        <form action="promotion.php" method="POST">
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <p>Click the button below to request admin access:</p>
            <button type="submit" class="btn btn-primary">Request Admin Access</button>
        </form>
        <a href="Member_dashboard.php" class="btn btn-link mt-2">Back to Dashboard</a>
    </div>
    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"></script>
</body>
</html>
