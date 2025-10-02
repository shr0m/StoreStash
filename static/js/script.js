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
        const row = input.closest("tr");

        const updateRowClass = () => {
            highlightRow(row);
        };

        // Initial highlight
        updateRowClass();

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

    highlightRow(row);
}

// Set quantity to 0
function removeQuantity(button) {
    const row = button.closest("tr");
    const input = row.querySelector(".quantity-input");
    input.value = 0;

    highlightRow(row);
}

// Collect and prepare stock data for batch update
function prepareUpdateData(event) {
    const rows = document.querySelectorAll("tbody tr");
    const data = [];

    rows.forEach(row => {
        const type = row.querySelector("td:nth-child(2)")?.innerText.trim();
        const sizing = row.querySelector("td:nth-child(3)")?.innerText.trim();
        const input = row.querySelector(".quantity-input");
        const categoryId = row.getAttribute("data-category-id");

        if (!input || !categoryId) return;

        const quantity = parseInt(input.value, 10);
        const original = parseInt(input.getAttribute("data-original"), 10);

        if (!isNaN(quantity) && quantity !== original) {
            data.push({
                type,
                sizing,
                quantity,
                category_id: categoryId
            });
        }
    });

    if (data.length === 0) {
        alert("No changes to update.");
        event.preventDefault();
        return false;
    }

    const hiddenInput = document.getElementById("update-data-input");
    if (!hiddenInput) {
        console.error("Hidden input #update-data-input not found.");
        event.preventDefault();
        return false;
    }

    hiddenInput.value = JSON.stringify(data);
    console.log("Submitting update data:", hiddenInput.value); // debug
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
function openStockModal(type, sizing, categoryId) {
    const modalTypeInput = document.getElementById("modal-stock-type");
    const modalSizingInput = document.getElementById("modal-stock-sizing");
    const modalCategoryInput = document.getElementById("modal-stock-category-id");
    const modalAlertInput = document.getElementById("modal-alert-threshold");

    modalTypeInput.value = type;
    modalSizingInput.value = sizing || "";   // handle null
    modalCategoryInput.value = categoryId;

    // Reset selects each time
    document.getElementById("modal-category-id").value = "";
    document.getElementById("modal-container-id").value = "";
    document.getElementById("modal-transfer-qty").value = "";

    // Find row based on type and sizing
    const row = Array.from(document.querySelectorAll("tbody tr")).find(r => {
        const rowType = r.querySelector("td:nth-child(2)")?.textContent.trim();
        const rowSizing = r.querySelector("td:nth-child(3)")?.textContent.trim() || "";
        return rowType === type && rowSizing === (sizing || "");
    });

    if (row) {
        let alertThreshold = row.getAttribute("data-alert-threshold");
        if (alertThreshold === "None" || alertThreshold === null) alertThreshold = "";
        modalAlertInput.value = alertThreshold;
    } else {
        modalAlertInput.value = "";
    }

    const modal = new bootstrap.Modal(document.getElementById("stock-modal"));
    modal.show();
}

function exportStockCSV() {
    const rows = document.querySelectorAll("table tbody tr");
    if (!rows.length) {
        alert("No stock data available to export.");
        return;
    }

    // CSV header
    const csvData = [["Category", "Type", "Sizing", "Quantity"]];

    rows.forEach(row => {
        const category = row.querySelector("td:nth-child(1)")?.textContent.trim() || "";
        const type = row.querySelector("td:nth-child(2)")?.textContent.trim() || "";
        const sizing = row.querySelector("td:nth-child(3)")?.textContent.trim() || "";
        const quantity = row.querySelector("td:nth-child(4)")?.textContent.trim() || "";

        csvData.push([category, type, sizing, quantity]);
    });

    // Convert array to CSV string
    const csvContent = csvData.map(e => e.map(v => `"${v.replace(/"/g, '""')}"`).join(",")).join("\n");

    // Download CSV
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `stock_export_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function highlightRow(row) {
    const threshold = parseInt(row.getAttribute("data-alert-threshold")) || 0;
    const input = row.querySelector(".quantity-input");
    const value = parseInt(input?.value) || 0;

    // Highlight red if below threshold
    row.classList.toggle("table-danger", threshold > 0 && value <= threshold);
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
            'X-CSRFToken': '{{ csrf_token() }}'
        },
        body: JSON.stringify({ person_id: personId, label_id: labelId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Error: ' + data.error);
            return;
        }

        const classList = Array.from(button.classList);
        const colorClass = classList.find(c => c.startsWith('btn-outline-') || c.startsWith('btn-'));

        if (!colorClass) return;

        const color = colorClass.replace('btn-outline-', '').replace('btn-', '');

        button.classList.remove(`btn-${color}`);
        button.classList.remove(`btn-outline-${color}`);

        if (data.status === 'added') {
            button.classList.add(`btn-${color}`);
        } else if (data.status === 'removed') {
            button.classList.add(`btn-outline-${color}`);
        }

        updateLabelsOnPersonCard(personId, data.assigned_labels || []);
    })
    .catch(err => {
        console.error('Toggle label error:', err);
        alert('An error occurred while toggling label.');
    });
}

function updateLabelsOnPersonCard(personId, assignedLabels) {
    const personCard = document.querySelector(`.person-card[data-person-id="${personId}"]`);
    if (!personCard) return;

    const badgeContainer = personCard.querySelector('.badge-container');
    if (!badgeContainer) return;

    // Clear existing badges and add fresh ones
    badgeContainer.innerHTML = assignedLabels.map(label =>
        `<span class="badge bg-${label.colour}" data-label-id="label-${label.id}">${label.name}</span>`
    ).join('');
}

function filterStockTable() {
    const input = document.getElementById("stock-search");
    const filter = input.value.toLowerCase();
    const rows = document.querySelectorAll("table tbody tr");

    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
    });
}