/* myprofile.html */
// Collect the input and preview image tags in a variable
const thumbInp = document.querySelector(".thumb-input");
const thumbPic = document.querySelectorAll(".thumb-picture");
const thumbOpacity = document.querySelectorAll(".thumb-opacity");

// Listen event when file input changed
thumbInp.addEventListener("change", () => {
    
    for (let i = 0; i < thumbPic.length; i++) {
        thumbPic[i].src = URL.createObjectURL(thumbInp.files[0]);
        
    }
    for (let i = 0; i < thumbOpacity.length; i++) {
        thumbOpacity[i].style.opacity = "1";
    }
})