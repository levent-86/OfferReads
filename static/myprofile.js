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
