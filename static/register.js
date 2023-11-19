// This file shared between myprofile.html, login.html, register.html
// The logic of this file is show/hide password while written

// Collect the inputs and icon in variables
const btn = document.querySelector(".pw-btn");
const inputs = document.querySelectorAll(".pw-inp");
const icon = document.querySelector(".bieye")

// Add event listener to button opacity
btn.addEventListener("mouseover", () => {
    btn.style.opacity = 1;
})
btn.addEventListener("mouseleave", () => {
    btn.style.opacity = .5;
})

// Add event listener to change input type for show/hide password
btn.addEventListener("click", () => {
    // Change the input type to "password" if it's "text"
    if (inputs[0].type == "text") {
        for (let i = 0; i < inputs.length; i++) {
            inputs[i].type = "password";
        }
    // Change the input type to "text" if it's "password"
    } else {
        for (let i = 0; i < inputs.length; i++) {
            inputs[i].type = "text";
        }
    }
    // Toggle button icon
    icon.classList.toggle("bi-eye");
    icon.classList.toggle("bi-eye-slash");
});
