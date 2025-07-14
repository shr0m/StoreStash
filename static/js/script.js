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
        const type = row.querySelector("td:nth-child(2)").innerText.trim();     // Name/Type
        const sizing = row.querySelector("td:nth-child(3)").innerText.trim();   // Sizing
        const input = row.querySelector(".quantity-input");
        const categoryId = row.getAttribute("data-category-id");

        if (!input || !categoryId) return;

        const quantity = parseInt(input.value, 10);
        const original = parseInt(input.getAttribute("data-original"), 10);

        if (quantity !== original) {
            hasChanges = true;
            data.push({
                type,        
                sizing,       
                quantity,
                category_id: categoryId
            });
        }
    });

    if (!hasChanges) {
        alert("No changes to update.");
        event.preventDefault();
        return false;
    }

    document.getElementById("update-data-input").value = JSON.stringify(data);
    // form submits normally
}

function filterPersonCards() {
    const filter = document.getElementById("stock-search").value.toLowerCase();
    const cards = document.querySelectorAll(".person-card");
    cards.forEach(card => {
        const name = card.getAttribute("data-name");
        card.style.display = name.includes(filter) ? "" : "none";
    });
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
  function openStockModal(type, sizing, currentCategoryId) {
    document.getElementById('modal-stock-type').value = type;
    document.getElementById('modal-stock-sizing').value = sizing || '';
    document.getElementById('modal-category-id').value = currentCategoryId;
    const modal = new bootstrap.Modal(document.getElementById('stock-modal'));
    modal.show();
  }

function setQuantity(event, index, parentIndex, type) {
    event.preventDefault();

    const qtyInput = document.getElementById(`qty-${index}-${parentIndex}`);
    if (!qtyInput) {
        alert("Quantity input field not found.");
        return;
    }

    const qty = parseInt(qtyInput.value);

    if (isNaN(qty) || qty <= 0) {
        alert("Please enter a valid quantity.");
        return;
    }

    const hiddenInputId = `${type}-hidden-${index}-${parentIndex}`;
    const hiddenInput = document.getElementById(hiddenInputId);
    if (hiddenInput) {
        hiddenInput.value = qty;
    } else {
        alert("Hidden input not found.");
        return;
    }

    // Submit the form manually
    event.target.closest("form").submit();
}

function toggleLabel(personId, labelId, button) {
    fetch('/toggle_label', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': '{{ csrf_token() }}' // if using CSRF
        },
        body: JSON.stringify({ person_id: personId, label_id: labelId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'added') {
            button.classList.remove('btn-outline-secondary');
            button.classList.add('btn-danger');
        } else if (data.status === 'removed') {
            button.classList.remove('btn-danger');
            button.classList.add('btn-outline-secondary');
        }
        // Optionally update badges on the card too
    });
}