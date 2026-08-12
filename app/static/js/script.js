const form = document.getElementById("scan-form");
const button = document.getElementById("scan-button");
const progress = document.getElementById("progress-container");

if (form) {
    form.addEventListener("submit", () => {
        button.disabled = true;
        button.textContent = "Analyzing…";
        progress.classList.remove("hidden");
    });
}
