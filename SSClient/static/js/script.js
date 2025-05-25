// Theme Toggle + Stock Form + Other Logic
document.addEventListener("DOMContentLoaded", function () {

    // Stock form validation
    const addForm = document.getElementById("add-stock-form");
    const typeInput = document.getElementById("new-type-input");

    if (addForm && typeInput) {
        addForm.addEventListener("submit", function (e) {
            const newType = typeInput.value.trim().toLowerCase();
            typeInput.classList.remove("invalid");

            const existingTypes = Array.from(document.querySelectorAll("tbody tr td:first-child"))
                .map(td => td.textContent.trim().toLowerCase());

            if (existingTypes.includes(newType)) {
                alert("This stock type already exists.");
                typeInput.classList.add("invalid");
                e.preventDefault();
            }
        });
    }
});

// Change quantity
function changeQuantity(button, delta) {
    const row = button.closest("tr");
    const input = row.querySelector(".quantity-input");
    let currentVal = parseInt(input.value) || 0;
    let newVal = currentVal + delta;
    if (newVal < 0) newVal = 0;
    input.value = newVal;
    row.classList.toggle("zero-stock", newVal === 0);
}

// Remove quantity
function removeQuantity(button) {
    const row = button.closest("tr");
    const input = row.querySelector(".quantity-input");
    input.value = 0;
    row.classList.add("zero-stock");
}

// Prepare data for update
function prepareUpdateData(event) {
    const rows = document.querySelectorAll("tbody tr");
    const data = [];
    let hasChanges = false;

    rows.forEach(row => {
        const itemId = row.getAttribute("data-item-id");
        const input = row.querySelector(".quantity-input");
        const quantity = parseInt(input.value);
        const original = parseInt(input.getAttribute("data-original"));

        if (quantity !== original) {
            hasChanges = true;
            data.push({ id: itemId, quantity });
        }
    });

    if (!hasChanges) {
        alert("No changes to update.");
        event.preventDefault();
        return false;
    }

    document.getElementById("update-data-input").value = JSON.stringify(data);
}

// Filter stock table
function filterStockTable() {
    const input = document.getElementById("stock-search");
    const filter = input.value.toLowerCase();
    const rows = document.querySelectorAll(".stock-table tbody tr");

    rows.forEach(row => {
        const typeCell = row.querySelector("td:first-child");
        const text = typeCell.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
    });
}