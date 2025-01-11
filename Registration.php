<?php
session_start();
include "db.php";

//csrf generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}    

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['error_message'] = 'Invalid CSRF token. Please try again.';
        header('Location: Registration.php');
        exit();
    }
    
    // Retrieve form data
    $first_name = $_POST['first_name'];
    $middle_name = $_POST['middle_name'];
    $last_name = $_POST['last_name'];
    $age = $_POST['age'];
    $marital_status = $_POST['marital_status'];
    $phone_number = $_POST['phone_number'];
    $dependant = $_POST['dependant'];
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $access_level = $_POST['access_level'];
    
    //check if role is admin
    
    if ($access_level === 'admin') {
        // Ensure user is logged in and get their user ID
        if (!isset($_SESSION['user_id'])) {
            $_SESSION['error_message'] = 'You must be logged in to request admin privileges.';
            header('Location: Registration.php');
            exit();
        }
        $current_user_id = $_SESSION['user_id'];
        
        $stmt = $conn->prepare("SELECT id FROM members WHERE Access_level = 'admin' LIMIT 1");
        $stmt->execute();
        $result = $stmt->get_result();
        $admin_id_row = $result->fetch_assoc();
        
        if ($admin_id_row) {
            $admin_id = $Admin_id_row['id'];

            // Verify if the current user is the admin
            if ($current_user_id !== $Admin_id) {
                $_SESSION['error_message'] = 'Only the current admin can approve new admin registrations.';
                header('Location: Registration.php');
                exit();
                
            }
        } else {
            $_SESSION['error_message'] = 'No admin found in the system.';
            header('Location: Registration.php');
            exit();
        }
        
         // Set the role to 'pending_admin' until approval
        $access_level = 'pending_admin';
    }
    
    // Check if username already exists
    $stmt = $conn->prepare("SELECT id FROM members WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    if ($stmt->get_result()->num_rows > 0) {
        $_SESSION['error_message'] = 'Username already exists. Please choose a different one.';
        header('Location: Registration.php');
        exit();
    }
    
     // Insert new user
    $stmt = $conn->prepare("INSERT INTO members (first_name, middle_name, last_name, age, marital_status, phone_number, dependant, username, password, access_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssiissss", $first_name, $middle_name, $last_name, $age, $marital_status, $phone_number, $dependant, $username, $password, $access_level);
    
    if ($stmt->execute()) {
        if ($access_level === 'pending_admin') {
            $_SESSION['message'] = 'Your request for admin access has been submitted. The current admin will review and approve or deny your request.';
            header('Location: Registration.php');
            exit();
        } else {
            $_SESSION['success_message'] = 'Registration successful. You can now log in.';
            header('Location: login.php');
            exit();
        }
    } else {
        $_SESSION['error_message'] = 'Error: ' . $conn->error;
        header('Location: Registration.php');
        exit();
    }
}

$conn->close();



?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>9Clan Registration</title>
    <!-- Bootstrap CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body>
    <div class="container">
        <h1 class="mt-4"><font color="#827b00" face="Lato">WELCOME TO 9CLAN NYAKAHURA WELFARE ASSOCIATION GROUP</font></h1>
        <p>Thank you for choosing to be part of our community!</p>
        <h2>Registration!</h2>
        
        <?php if (isset($_SESSION['error_message'])): ?>
            <div class="alert alert-danger" Access_level="alert">
                <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?>
            </div>
        <?php endif; ?>
        <?php if (isset($_SESSION['success_message'])): ?>
            <div class="alert alert-success" Access_level="alert">
                <?php echo $_SESSION['success_message']; unset($_SESSION['success_message']); ?>
            </div>
        <?php endif; ?>
        <?php if (isset($_SESSION['message'])): ?>
            <div class="alert alert-info" Access_level="alert">
                <?php echo $_SESSION['message']; unset($_SESSION['message']); ?>
            </div>
        <?php endif; ?>
        <form action="Registration.php" method="POST" onsubmit="return confirm('Are you sure all your details are correct?');">
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
       
            
            <div class="form-group">
                <label for="first_name">First Name:</label>
                <input type="text" class="form-control" id="first_name" name="first_name" required>
            </div>
            <div class="form-group">
                <label for="middle_name">Middle Name:</label>
                <input type="text" class="form-control" id="middle_name" name="middle_name">
            </div>
            <div class="form-group">
                <label for="last_name">Last Name:</label>
                <input type="text" class="form-control" id="last_name" name="last_name" required>
            </div>
            <div class="form-group">
                <label for="age">Age:</label>
                <input type="number" class="form-control" id="age" name="age" required>
            </div>
            <div class="form-group">
                <label for="marital_status">Marital Status:</label>
                <select class="form-control" id="marital_status" name="marital_status" required>
                    <option value="single">Single</option>
                    <option value="married">Married</option>
                    <option value="divorced">Divorced</option>
                </select>
            </div>
            <div class="form-group">
                <label for="phone_number">Phone Number:</label>
                <input type="text" class="form-control" id="phone_number" name="phone_number" required>
            </div>
            <div class="form-group">
                <label for="dependant">Dependant:</label>
                <input type="number" class="form-control" id="dependant" name="dependant">
            </div>
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" class="form-control" id="password" name="password" required>
                <input type="hidden" name="Access_level" value="member">
            </div>
            <div class="form-group">
                <label for="Access_level">Access_level:</label>
                <select class="form-control" id="Access_level" name="Access_level" required>
                    <option value="member">member</option>
                    <option value="admin">admin (requires approval)</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
        <a href="login.php" class="btn btn-link mt-3">Already a member? Login here</a>
    </div>
    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js" integrity="sha384-oBqDVmMz4fnFO9g3jJ8jH5kSlzj8gAaAAmkD0S/2L3fUv0/3C4C3ffUHUxHs0z9e" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>
