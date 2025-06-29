// Theme Toggle + Stock Form + Other Logic
document.addEventListener("DOMContentLoaded", function () {
    const addForm = document.getElementById("add-stock-form");
    const typeInput = document.getElementById("new-type-input");

    if (addForm && typeInput) {
        addForm.addEventListener("submit", function (e) {
            const newType = typeInput.value.trim().toLowerCase();
            typeInput.classList.remove("is-invalid");

            const existingTypes = Array.from(document.querySelectorAll("tbody tr td:nth-child(1)"))
                .map(td => td.textContent.trim().toLowerCase());

            if (existingTypes.includes(newType)) {
                alert("This stock type already exists.");
                typeInput.classList.add("is-invalid");  // Bootstrap's invalid class
                e.preventDefault();
            }
        });
    }

    // Handle highlighting rows with zero quantity
    document.querySelectorAll(".quantity-input").forEach(input => {
        const updateRowClass = () => {
            const row = input.closest("tr");
            const value = parseInt(input.value) || 0;
            input.value = value;
            row.classList.toggle("table-danger", value === 0);  // Bootstrap class for red row
        };

        input.addEventListener("input", updateRowClass);
        input.addEventListener("blur", updateRowClass);
    });
});

// Change quantity
function changeQuantity(button, delta) {
    const row = button.closest("tr");
    const input = row.querySelector(".quantity-input");
    let currentVal = parseInt(input.value) || 0;
    let newVal = currentVal + delta;
    if (newVal < 0) newVal = 0;
    input.value = newVal;
    row.classList.toggle("table-danger", newVal === 0);
}

// Set quantity to 0
function removeQuantity(button) {
    const row = button.closest("tr");
    const input = row.querySelector(".quantity-input");
    input.value = 0;
    row.classList.add("table-danger");
}

// Collect and prepare stock data for batch update
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

    // Match any table with tbody tr
    const rows = document.querySelectorAll("table tbody tr");

    rows.forEach(row => {
        const typeCell = row.querySelector("td:nth-child(1)");
        if (!typeCell) return;

        const text = typeCell.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
    });
}

// Open Bootstrap modal
function openModal(button) {
    const row = button.closest("tr");
    const itemType = row.querySelector("td:nth-child(1)").innerText;
    const modalLabel = document.getElementById("modal-item-type");
    modalLabel.innerText = itemType;

    const modal = new bootstrap.Modal(document.getElementById("stock-modal"));
    modal.show();
}
