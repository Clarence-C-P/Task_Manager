function validateLogIn() {
const email = document.getElementById("email").value;
const password = document.getElementById("password").value;
const fullName = document.getElementById("fullName").value;
const confirmPassword = document.getElementById("confirmPassword").value;

let errorMessage = "";

if (!email) {
    errorMessage += "Email is required. \n";
} 
else if (email.length < 5) {
    errorMessage += "Email must be 4 characters long. \n";
}

if (!password) {
    errorMessage += "Password is required. \n";

} else if (password.length < 5) {
    errorMessage += "Password must be 4 characters long. \n";
}

else if (password !== confirmPassword) {
    errorMessage += "Password does not match. \n";
}
if (!fullName){
    errorMessage += "Name is Required. \n";
}
if (errorMessage) {
    alert(errorMessage);
    return false;
}

return true;

}