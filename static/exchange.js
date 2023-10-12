// Collect the input and preview image tags in a variable
const imgInput = document.querySelector(".img-input");
const imgWarn = document.querySelector(".image-warn");
const imgParent = document.getElementById("image-node");
const textArea = document.querySelector(".exc-form-control")
const charCounter = document.querySelector(".counter")

// Accept only .jpg, .jpeg, .png, .gif file formats
imgInput.accept = ".jpg, .jpeg, .png, .gif";

// Listen event to clean previous selected images
imgInput.addEventListener("change", () => {
    // Ensure if there's an image
    if (imgParent.hasChildNodes() && imgInput.files.length <= 10) {
        // Delete all previous images
        while (imgParent.children[0]) {
            imgParent.children[0].remove();
        }
    }
})


// Listen event when file input changed and preview new selected images
imgInput.addEventListener("change", () => {

    // Warn user if they trying to upload more than 10 images
    if (imgInput.files.length > 10) {
        imgWarn.innerHTML = `Warning! You choose ${imgInput.files.length} images.`;
    } else {
        // If user selects less than 11 images, remove the warning.
        imgWarn.innerHTML = "";

        // Iterate selected images times to create img tag(s)
        for (let i = 0; i < imgInput.files.length; i++) {
            // Create <img> tag and it's necessary attributions
            const imgTag = document.createElement("img");
            const srcAttr = document.createAttribute("src");
            const classAttr = document.createAttribute("class");

            // Set attributions in <img> tag and place it under the parent node
            imgTag.setAttributeNode(srcAttr);
            imgTag.setAttributeNode(classAttr);
            imgParent.appendChild(imgTag);

            // Fill attributions inside the <img> tag
            classAttr.value = "book-picture rounded mb-4";
            srcAttr.value = URL.createObjectURL(imgInput.files[i]);
        }
    }
})

// Resize the <textarea> tag when clicked
textArea.addEventListener("click", () => {
    textArea.style.height = "15rem";
})

// Count the characters on the <textarea> tag
textArea.addEventListener("keyup", () => {
    charCounter.innerHTML = 600 - textArea.value.length;
})
