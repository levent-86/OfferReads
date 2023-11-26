// index part
// Search bar

const searchBar = document.querySelector('.form-control');
const cards = document.querySelectorAll(".prev-card-deck");

// Deprecate the featured books when user uses the search bar
searchBar.addEventListener("input", () => {
    for (let i = 0; i < cards.length; i++) {
        // Deprecate the featured books when search bar in use, display if not in use
        if (searchBar.value) {
            cards[i].style.display = "none";
        } else {
            cards[i].style.display = "block";
        }
    }
})

// https://cs50.harvard.edu/x/2023/weeks/9/
// https://cdn.cs50.net/2022/fall/lectures/9/src9.pdf
searchBar.addEventListener('input', async function() {
    let response = await fetch('/search?q=' + searchBar.value);
    let books = await response.json();
    let html = '';
    for (let id in books) {
        let title = books[id].title.replace('<', '&lt;').replace('&', '&amp;');
        let author = books[id].author.replace('<', '&lt;').replace('&', '&amp;');
        let condition = ""
        if (books[id].condition) {
            condition = `<p class="card-text card-capitalize">Condition: ${books[id].condition}</p>`
        } else {
            condition = `<p class="card-text card-capitalize">No Condition Information</p>`
        }
        let userName = books[id].username;
        let userId = books[id].userid;
        let bookId = books[id].bookid;
        let date = books[id].date;
        let images = "";
        if (books[id].image) {
            images = `<a href="book/${bookId + title}"><img class="card-img-top" src="../static/pictures/${userId}/bp/${books[id].image}" alt="Card image" style="height: 18rem; width: 18rem; object-fit: cover;"></a>`
        } else {
            images = `<a href="book/${bookId + title}"><img class="card-img-top" src="../static/book-circle.svg" alt="Card image" style="height: 18rem; width: 18rem; object-fit: cover; opacity: .5;"></a>`
        }
        
        html += `<div class="card-deck mt-5 mb-5">
        <div class="card mb-4" style="width: 18rem; height: 36rem;" >
        ${images}
        <div class="card-body d-flex flex-column justify-content-around">
        <h5 class="card-title index-card card-capitalize">${title}</h5>
        <p class="card-text card-capitalize">${author}</p>
        ${condition}
        <span>Exchanger: </span><a href="user/${userName}"><p class="card-text">${userName}</p></a>
        </div>
        <div class="card-footer">
        <small class="text-muted">${date}</small>
        </div>
        </div>
        </div>`;
    }
    document.querySelector('.new-card-deck').innerHTML = html;
});


// Pagination buttons
const select = document.querySelector(".index-option");
const form = document.querySelector(".index-form");

select.addEventListener("change", () => {
    // https://www.w3schools.com/jsref/met_form_submit.asp
    form.submit();
})
