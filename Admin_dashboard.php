<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];
$access_level = $_SESSION['access_level'];

// Fetch the current admin user ID
$Admin_id = $user_id; // This is assuming the current logged-in user is the admin

if ($access_level == 'admin') {
    
    header('Location: Admin_dashboard.php');
        //Redirect non-admin users
    exit();
    
    if (isset($_POST['delete'])) {
        $member_id = $_POST['delete'];

        $stmt = $conn->prepare("DELETE FROM members WHERE id=?");
        $stmt->bind_param("i", $member_id);
        if ($stmt->execute()) {
            echo "<div class='alert alert-success'>Member deleted.</div>";
        } else {
            echo "<div class='alert alert-danger'>Error: " . $conn->error . "</div>";
        }
    }

    if (isset($_POST['update'])) {
        $member_id = $_POST['member_id'];
        $first_name = $_POST['first_name'];
        $middle_name = $_POST['middle_name'];
        $last_name = $_POST['last_name'];
        $age = $_POST['age'];
        $marital_status = $_POST['marital_status'];
        $phone_number = $_POST['phone_number'];
        $dependant = $_POST['dependant'];
        $monthly_contribution = $_POST['monthly_contribution'];
        $funeral_contribution = $_POST['funeral_contribution'];
        $monthly_penalty = $_POST['monthly_penalty'];
        $funeral_penalty = $_POST['funeral_penalty'];

        $stmt = $conn->prepare("UPDATE members SET first_name=?, middle_name=?, last_name=?, age=?, marital_status=?, phone_number=?, dependant=?, monthly_contribution=?, funeral_contribution=?, monthly_penalty=?, funeral_penalty=? WHERE id=?");
        $stmt->bind_param("sssiissiiiii", $first_name, $middle_name, $last_name, $age, $marital_status, $phone_number, $dependant, $monthly_contribution, $funeral_contribution, $monthly_penalty, $funeral_penalty, $member_id);
        if ($stmt->execute()) {
            echo "<div class='alert alert-success'>Member updated.</div>";
        } else {
            echo "<div class='alert alert-danger'>Error: " . $conn->error . "</div>";
        }
    }

    if (isset($_POST['promote'])) {
        $member_id = $_POST['member_id'];

        // Check if the client is already an admin
        $stmt = $conn->prepare("SELECT role FROM members WHERE id=?");
        $stmt->bind_param("i", $access_level_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $member = $result->fetch_assoc();

        if ($member['access_level'] == 'admin') {
            echo "<div class='alert alert-warning'>This user is already an admin.</div>";
        } else {
            // Promote the client to admin
            $stmt = $conn->prepare("UPDATE members SET access_level='admin' WHERE id=?");
            $stmt->bind_param("i", $member_id);
            if ($stmt->execute()) {
                echo "<div class='alert alert-success'>Client promoted to admin.</div>";
            } else {
                echo "<div class='alert alert-danger'>Error: " . $conn->error . "</div>";
            }
        }
    }

    // Ensure the admin is the only one who can promote others
    if ($user_id !== $admin_id) {
        echo "<div class='alert alert-danger'>You do not have permission to perform this action.</div>";
        exit();
    }
}

$stmt = $conn->prepare("SELECT * FROM members");
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <style>
        body {
            background-color: #e8f5e9;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            margin-top: 50px;
        }
        h2, h3 {
            color: #388e3c;
        }
        .btn-primary {
            background-color: #2e7d32;
            border-color: #2e7d32;
        }
        .btn-primary:hover {
            background-color: #1b5e20;
            border-color: #1b5e20;
        }
        .btn-danger {
            background-color: #d32f2f;
            border-color: #d32f2f;
        }
        .btn-danger:hover {
            background-color: #c62828;
            border-color: #c62828;
        }
        .table th {
            background-color: #388e3c;
            color: white;
        }
        .alert {
            margin-bottom: 20px;
        }
        .card {
            border: none;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            background-color: #388e3c;
            color: white;
        }
        .card-body {
            background-color: #f1f8e9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="text-center mb-4">ADMIN DASHBOARD</h2>

        <!-- Update Member Details -->
        <div class="card mb-4">
            <div class="card-header">
                <h3>Update Member Details</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="">
                    <div class="mb-3">
                        <label for="member_id" class="form-label">Member ID:</label>
                        <input type="text" class="form-control" id="member_id" name="member_id" required>
                    </div>
                    <div class="mb-3">
                        <label for="first_name" class="form-label">First Name:</label>
                        <input type="text" class="form-control" id="first_name" name="first_name" required>
                    </div>
                    <div class="mb-3">
                        <label for="middle_name" class="form-label">Middle Name:</label>
                        <input type="text" class="form-control" id="middle_name" name="middle_name">
                    </div>
                    <div class="mb-3">
                        <label for="last_name" class="form-label">Last Name:</label>
                        <input type="text" class="form-control" id="last_name" name="last_name" required>
                    </div>
                    <div class="mb-3">
                        <label for="age" class="form-label">Age:</label>
                        <input type="number" class="form-control" id="age" name="age" required>
                    </div>
                    <div class="mb-3">
                        <label for="marital_status" class="form-label">Marital Status:</label>
                        <input type="text" class="form-control" id="marital_status" name="marital_status" required>
                    </div>
                    <div class="mb-3">
                        <label for="phone_number" class="form-label">Phone Number:</label>
                        <input type="text" class="form-control" id="phone_number" name="phone_number" required>
                    </div>
                    <div class="mb-3">
                        <label for="dependant" class="form-label">Dependant:</label>
                        <input type="text" class="form-control" id="dependant" name="dependant" required>
                    </div>
                    <div class="mb-3">
                        <label for="monthly_contribution" class="form-label">Monthly Contribution:</label>
                        <input type="number" class="form-control" id="monthly_contribution" name="monthly_contribution" required>
                    </div>
                    <div class="mb-3">
                        <label for="funeral_contribution" class="form-label">Funeral Contribution:</label>
                        <input type="number" class="form-control" id="funeral_contribution" name="funeral_contribution" required>
                    </div>
                    <div class="mb-3">
                        <label for="monthly_penalty" class="form-label">Monthly Penalty:</label>
                        <input type="number" class="form-control" id="monthly_penalty" name="monthly_penalty" required>
                    </div>
                    <div class="mb-3">
                        <label for="funeral_penalty" class="form-label">Funeral Penalty:</label>
                        <input type="number" class="form-control" id="funeral_penalty" name="funeral_penalty" required>
                    </div>
                    <button type="submit" name="update" class="btn btn-primary">Update Details</button>
                </form>
            </div>
        </div>

        <!-- Delete Member -->
        <div class="card mb-4">
            <div class="card-header">
                <h3>Delete Member</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="">
                    <div class="mb-3">
                        <label for="delete" class="form-label">Member ID to Delete:</label>
                        <input type="text" class="form-control" id="delete" name="delete" required>
                    </div>
                    <button type="submit" class="btn btn-danger">Delete Member</button>
                </form>
            </div>
        </div>

        <!-- Promote Client -->
        <div class="card mb-4">
            <div class="card-header">
                <h3>Promote Client</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="">
                    <div class="mb-3">
                        <label for="client_id" class="form-label">Client ID to Promote:</label>
                        <input type="text" class="form-control" id="client_id" name="client_id" required>
                    </div>
                    <button type="submit" name="promote" class="btn btn-primary">Promote to Admin</button>
                </form>
            </div>
        </div>

        <!-- View All Members -->
        <div class="card">
            <div class="card-header">
                <h3>All Members</h3>
            </div>
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>First Name</th>
                            <th>Middle Name</th>
                            <th>Last Name</th>
                            <th>Age</th>
                            <th>Marital Status</th>
                            <th>Phone Number</th>
                            <th>Dependant</th>
                            <th>Monthly Contribution</th>
                            <th>Funeral Contribution</th>
                            <th>Monthly Penalty</th>
                            <th>Funeral Penalty</th>
                            <th>Access_level</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $result->fetch_assoc()) { ?>
                            <tr>
                                <td><?php echo htmlspecialchars($row['id']); ?></td>
                                <td><?php echo htmlspecialchars($row['first_name']); ?></td>
                                <td><?php echo htmlspecialchars($row['middle_name']); ?></td>
                                <td><?php echo htmlspecialchars($row['last_name']); ?></td>
                                <td><?php echo htmlspecialchars($row['age']); ?></td>
                                <td><?php echo htmlspecialchars($row['marital_status']); ?></td>
                                <td><?php echo htmlspecialchars($row['phone_number']); ?></td>
                                <td><?php echo htmlspecialchars($row['dependant']); ?></td>
                                <td><?php echo htmlspecialchars($row['monthly_contribution']); ?></td>
                                <td><?php echo htmlspecialchars($row['funeral_contribution']); ?></td>
                                <td><?php echo htmlspecialchars($row['monthly_penalty']); ?></td>
                                <td><?php echo htmlspecialchars($row['funeral_penalty']); ?></td>
                                <td><?php echo htmlspecialchars($row['access_level']); ?></td>
                            </tr>
                        <?php } ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
