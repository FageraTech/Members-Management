<?php
session_start();
include 'db.php';

// Generate CSRF token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];
$access_level = $_SESSION['access_level'];

//debugging log in user ID and access level

error_log("User ID: " . $user_id);
error_log("Access Level: " . $access_level);

// Check if the logged-in user is a member and not an admin
if ($access_level !== 'member') {
   echo "Unauthorized access";
    exit();
}

// Fetch user information
$stmt = $conn->prepare("SELECT * FROM members WHERE id=?");
if ($stmt === false) {
    error_log("Prepare failed: " . htmlspecialchars($conn->error));
    header('Location: index.php?message=Error preparing statement.');
    exit();
}

$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$member = $result->fetch_assoc();

// Check if member data was fetched
if (!$member) {
    error_log("No member found with id: " . htmlspecialchars($user_id));
    header('Location: index.php?message=Error fetching user data. Please try again later.');
    exit();
}

// Handle user information update
if (isset($_POST['update'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        header('Location: Members_dashboard.php?message=Invalid CSRF token');
        exit();
    }

    // Sanitize and validate input
    $first_name = htmlspecialchars($_POST['first_name']);
    $middle_name = htmlspecialchars($_POST['middle_name']);
    $last_name = htmlspecialchars($_POST['last_name']);
    $age = filter_var($_POST['age'], FILTER_VALIDATE_INT);
    $marital_status = htmlspecialchars($_POST['marital_status']);
    $phone_number = htmlspecialchars($_POST['phone_number']);
    $dependant = filter_var($_POST['dependant'], FILTER_VALIDATE_INT);

    // Validate age and dependant
    if ($age === false || $dependant === false) {
        header('Location: Members_dashboard.php?message=Invalid age or dependant value.');
        exit();
    } else {
        // Update user information
        $stmt = $conn->prepare("UPDATE clients SET first_name=?, middle_name=?, last_name=?, age=?, marital_status=?, phone_number=?, dependant=? WHERE id=?");
        if ($stmt === false) {
            error_log("Prepare failed: " . htmlspecialchars($conn->error));
            header('Location: Members_dashboard.php?message=Error preparing statement.');
            exit();
        }
        $stmt->bind_param("sssiisii", $first_name, $middle_name, $last_name, $age, $marital_status, $phone_number, $dependant, $user_id);
        
        if ($stmt->execute()) {
            header('Location: Members_dashboard.php?message=Information updated successfully');
            exit();
        } else {
            error_log("Update error: " . $conn->error);
            header('Location: Members_dashboard.php?message=Error updating information. Please try again later.');
            exit();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Members Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #e8f5e9; /* Light green background */
        }
        .container {
            background-color: #ffffff; /* White container */
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            margin-top: 50px;
        }
        h2, h3 {
            color: #388e3c; /* Dark green color for headers */
        }
        .btn-primary {
            background-color: #2e7d32; /* Green button */
            border-color: #2e7d32;
        }
        .btn-primary:hover {
            background-color: #1b5e20; /* Darker green on hover */
            border-color: #1b5e20;
        }
        .alert {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="text-center mb-4">Members Dashboard</h2>
            <a href="logout.php">Logout</a>

        <?php if (isset($_GET['message'])): ?>
            <div class="alert alert-info"><?php echo htmlspecialchars($_GET['message']); ?></div>
        <?php endif; ?>

        <h3>Update Your Information</h3>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="mb-3">
                <label for="first_name" class="form-label">First Name:</label>
                <input type="text" class="form-control" id="first_name" name="first_name" value="<?php echo htmlspecialchars($member['first_name']); ?>" required aria-required="true">
            </div>
            <div class="mb-3">
                <label for="middle_name" class="form-label">Middle Name:</label>
                <input type="text" class="form-control" id="middle_name" name="middle_name" value="<?php echo htmlspecialchars($member['middle_name']); ?>">
            </div>
            <div class="mb-3">
                <label for="last_name" class="form-label">Last Name:</label>
                <input type="text" class="form-control" id="last_name" name="last_name" value="<?php echo htmlspecialchars($member['last_name']); ?>" required aria-required="true">
            </div>
            <div class="mb-3">
                <label for="age" class="form-label">Age:</label>
                <input type="number" class="form-control" id="age" name="age" value="<?php echo htmlspecialchars($member['age']); ?>" required min="0" max="120" aria-required="true">
            </div>
            <div class="mb-3">
                <label for="marital_status" class="form-label">Marital Status:</label>
                <select class="form-control" id="marital_status" name="marital_status" required aria-required="true">
                    <option value="single" <?php echo $member['marital_status'] === 'single' ? 'selected' : ''; ?>>Single</option>
                    <option value="married" <?php echo $member['marital_status'] === 'married' ? 'selected' : ''; ?>>Married</option>
                    <option value="divorced" <?php echo $member['marital_status'] === 'divorced' ? 'selected' : ''; ?>>Divorced</option>
                </select>
            </div>
            <div class="mb-3">
                <label for="phone_number" class="form-label">Phone Number:</label>
                <input type="text" class="form-control" id="phone_number" name="phone_number" value="<?php echo htmlspecialchars($member['phone_number']); ?>" required pattern="\d{10}" title="Please enter a valid 10-digit phone number" aria-required="true">
            </div>
            <div class="mb-3">
                <label for="dependant" class="form-label">Dependant:</label>
                <input type="number" class="form-control" id="dependant" name="dependant" value="<?php echo htmlspecialchars($member['dependant']); ?>" min="0">
            </div>
            <button type="submit" name="update" class="btn btn-primary">Update Information</button>
        </form>

        <hr>
        <h3>Your Contributions and Penalties</h3>
        <p><strong>Monthly Contribution:</strong> <?php echo htmlspecialchars($member['monthly_contribution']); ?></p>
        <p><strong>Funeral Contribution:</strong> <?php echo htmlspecialchars($member['funeral_contribution']); ?></p>
        <p><strong>Monthly Penalty:</strong> <?php echo htmlspecialchars($member['monthly_penalty']); ?></p>
        <p><strong>Funeral Penalty:</strong> <?php echo htmlspecialchars($member['funeral_penalty']); ?></p>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js" integrity="sha384-oBqDVmMz4fnFO9g3jJ8jH5kSlzj8gAaAAmkD0S/2L3fUv0/3C4C3ffUHUxHs0z9e" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>
