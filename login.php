<?php
session_start();
include 'db.php';

// Generate CSRF token if not already set
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['error_message'] = 'Invalid CSRF token. Please try again.';
        header('Location: login.php');
        exit();
    }

    // Retrieve form data
    $username = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);

    // Prepare and execute query to check if the user exists
    $stmt = $conn->prepare("SELECT id, username, password, access_level FROM members WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row['password'])) {
            // Set session variables
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];
            $_SESSION['access_level'] = $row['access_level'];

            // Redirect based on role
            if ($row['access_level'] === 'admin') {
                header('Location: Admin_dashboard.php');
            } elseif($user["access_level"] ==="member") {
                header('Location: Member_dashboard.php');
            } else {
                echo "unauthorized access!";
            }
            exit();
            
        } else {
            $_SESSION['error_message'] = 'Invalid password. Please try again.';
        }
    } else {
        $_SESSION['error_message'] = 'Invalid username or password. Please try again.';
    }
    // Redirect back to login if there was an error
    header('Location: login.php');
    exit();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <!-- Bootstrap CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
           
</head>
<body>
    <div class="container">
        <h2 class="mt-4"><font color="#827b00" face="Lato">Login</font></h2>
        <p>Please enter your details.</p>
        <?php if (isset($_SESSION['error_message'])): ?>
            <div class="alert alert-danger" role="alert">
                <?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?>
            </div>
        <?php endif; ?>
        <form action="login.php" method="POST">
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <div class="form-group mb-3">
                <label for="username">Username:</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="form-group mb-3">
                <label for="password">Password:</label>
                <input type="password" class="form-control" id="password" name="password" required>
                <input type="checkbox" onclick="togglePassword()"> Show Password
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <a href="Registration.php" class="btn btn-link mt-2">Don't have an account? Register here</a>
    </div>
    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"></script>
    <script>
        function togglePassword() {
            var passwordField = document.getElementById("password");
            passwordField.type = (passwordField.type === "password") ? "text" : "password";
        }
    </script>
</body>
</html>
