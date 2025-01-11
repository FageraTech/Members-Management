<?php
session_start();
include 'db.php';

// Set kKen's details
$first_name = 'Mart';
$middle_name = 'Ken';
$last_name = 'Mwangi';
$age = 40;
$marital_status = 'single';
$phone_number = '+254737051813';
$dependant = 0;
$username = 'Kamunya_100';
$password = 'Kamunya100'; // Original password (for hashing)
$hashed_password = password_hash($password, PASSWORD_BCRYPT); // Hash the password
$Access_level = 'Admin';

// Check if the username already exists
$stmt = $conn->prepare("SELECT id FROM members WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    // Username exists, update the existing record
    $stmt = $conn->prepare("UPDATE members SET first_name = ?, middle_name = ?, last_name = ?, age = ?, marital_status = ?, phone_number = ?, dependant = ?, password = ?, Access_level = ? WHERE username = ?");
    $stmt->bind_param("ssssiissss", $first_name, $middle_name, $last_name, $age, $marital_status, $phone_number, $dependant, $hashed_password, $Access_level, $username);

    if ($stmt->execute()) {
        echo 'Kamunya\'s record has been updated successfully.';
    } else {
        echo 'Error updating record: ' . $conn->error;
    }
    
    $stmt->close();
} else {
    // Insert Dan Mbatia as the initial admin
    $stmt = $conn->prepare("INSERT INTO members (first_name, middle_name, last_name, age, marital_status, phone_number, dependant, username, password, Access_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssiissss", $first_name, $middle_name, $last_name, $age, $marital_status, $phone_number, $dependant, $username, $hashed_password, $Access_level);

    if ($stmt->execute()) {
        echo 'Kamunya has been added as the initial admin.';
    } else {
        echo 'Error inserting record: ' . $conn->error;
    }
    
    $stmt->close();
}

$conn->close();
?>
