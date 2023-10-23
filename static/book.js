// Image modal part
// Collect images in variables
const allImages = document.querySelectorAll(".each-image");
const modal = document.querySelectorAll(".book-modal")

// Iterate over each small images to increase the size of images
for (let i = 0; i < allImages.length; i++) {
    allImages[i].addEventListener("click", () => {
        modal[i].classList.remove("image-close");
        modal[i].classList.add("image-open");
    })
}

// Iterate over each big size image to close modal
for (let i = 0; i < modal.length; i++) {
    modal[i].addEventListener("click", () => {
        modal[i].classList.add("image-close");
        modal[i].classList.remove("image-open");
    })
}

// Offer modal part
const offerBtn = document.querySelector(".offer-btn");
const offerCancel = document.querySelector(".offer-cancel")
const offerModal = document.querySelector(".offer-modal")

offerBtn.addEventListener("click", () => {
    offerModal.classList.remove("offer-close");
    offerModal.classList.add("offer-open");
})

offerCancel.addEventListener("click", () => {
    offerModal.classList.add("offer-close");
    offerModal.classList.remove("offer-open");
})
