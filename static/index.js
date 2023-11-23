const searchBar = document.querySelector(".form-control");
const card = document.querySelectorAll(".card-deck");
const cardTitle = document.querySelectorAll(".card-title");

searchBar.addEventListener("keyup", () => {
    for (let i = 0; i < card.length; i++) {
        if (cardTitle[i].innerHTML.toLowerCase().search(searchBar.value.toLowerCase()) > -1) {
            card[i].style.display = "block";
        }
        else {
            card[i].style.display = "none";
        }
    }
})
