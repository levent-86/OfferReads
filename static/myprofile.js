// Collect the input and preview image tags in a variable
const previewInp = document.querySelector(".preview-input");
const previewPic = document.querySelectorAll(".preview-picture");
const previewOpacity = document.querySelectorAll(".preview-opacity");

// Accept only .jpg, .jpeg, .png, .gif file formats
previewInp.accept = ".jpg, .jpeg, .png, .gif";

// Listen event when file input changed
previewInp.addEventListener("change", () => {
    // Preview the image
    for (let i = 0; i < previewPic.length; i++) {
        previewPic[i].src = URL.createObjectURL(previewInp.files[0]);
    }
    // Change the opacity of image
    for (let i = 0; i < previewOpacity.length; i++) {
        previewOpacity[i].style.opacity = "1";
    }
})

// Delete account modal
// Collect the account deletion buttons and container in a variable
const delBtn = document.querySelector(".del-btn");
const cancelBtn = document.querySelector(".acc-del-cancel")
const delContainer = document.querySelector(".acc-del-container");

// Listen event and show the delete/cancel buttons when Delete Your Account button clicked
delBtn.addEventListener("click", () => {
    delContainer.classList.remove("acc-del-close")
    delContainer.classList.add("acc-del-open")
})
// Listen event and hide the delete/cancel buttons when Cancel button clicked
cancelBtn.addEventListener("click", () => {
    delContainer.classList.remove("acc-del-open");
    delContainer.classList.add("acc-del-close");
})
