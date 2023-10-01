// myprofile.html section
const btn = document.querySelector(".mp-show");
const edit = document.querySelector(".mp-hidden");

btn.addEventListener("click", () => {
    const disabled = document.querySelectorAll(".mp-disabled");
    for (let i = 0; i < disabled.length; i++) {
        disabled[i].disabled = false;
    }
    btn.classList.add("mp-hidden");
    btn.classList.remove("mp-show");
    edit.classList.remove("mp-hidden");
})
