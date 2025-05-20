document.addEventListener("DOMContentLoaded", function () {
    const addForm = document.getElementById("add-stock-form");
    const typeInput = document.getElementById("new-type-input");

    addForm.addEventListener("submit", function (e) {
        const newType = typeInput.value.trim().toLowerCase();

        // Reset styles
        typeInput.classList.remove("invalid");

        // Get existing types
        const existingTypes = Array.from(document.querySelectorAll("tbody tr td:first-child"))
            .map(td => td.textContent.trim().toLowerCase());

        let hasError = false;

        // Validation: duplicate type
        if (existingTypes.includes(newType)) {
            alert("This stock type already exists.");
            typeInput.classList.add("invalid");
            hasError = true;
        }

        if (hasError) {
            e.preventDefault();
        }
    });
});

function changeQuantity(button, delta) {
    const row = button.closest('tr');
    const input = row.querySelector('.quantity-input');
    let currentVal = parseInt(input.value) || 0;
    let newVal = currentVal + delta;
    if (newVal < 0) newVal = 0;
    input.value = newVal;

    // Visual cue if zero
    row.classList.toggle('zero-stock', newVal === 0);
}

function removeQuantity(button) {
    const row = button.closest('tr');
    const input = row.querySelector('.quantity-input');
    let newVal = 0;
    input.value = newVal;

    // Visual cue if zero
    row.classList.toggle('zero-stock', newVal === 0);
}

function prepareUpdateData(event) {
    const rows = document.querySelectorAll('tbody tr');
    const data = [];
    let hasChanges = false;

    rows.forEach(row => {
        const itemId = row.getAttribute('data-item-id');
        const input = row.querySelector('.quantity-input');
        const quantity = parseInt(input.value);
        const original = parseInt(input.getAttribute('data-original'));

        if (quantity !== original) {
            hasChanges = true;
            data.push({ id: itemId, quantity });
        }
    });

    if (!hasChanges) {
        alert("No changes to update.");
        event.preventDefault(); // Cancel form submission
        return false;
    }

    document.getElementById('update-data-input').value = JSON.stringify(data);
}