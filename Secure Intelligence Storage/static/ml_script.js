document.addEventListener("DOMContentLoaded", function () {
    const anomalyButton = document.getElementById("anomalyButton");
    const anomalyTable = document.querySelector("#anomalyTable tbody");
    // Adding a click event listener to trigger anomaly detection
    anomalyButton.addEventListener("click", function () {
        console.log("Checking for file anomalies...");
        // Make a GET request to the server endpoint
        fetch("/get_file_anomalies")
            .then(response => response.json())
            .then(data => {
                anomalyTable.innerHTML = "";
                // Handle server errors (backend might return JSON error object)
                if (!Array.isArray(data)) {
                    console.error("Backend returned error:", data.error || data);
                    anomalyTable.innerHTML = "<tr><td colspan='5'> Server error. Check console.</td></tr>";
                    return;
                }
                // If no anomalies are detected, show a message
                if (data.length === 0) {
                    anomalyTable.innerHTML = "<tr><td colspan='5'>No anomalies detected</td></tr>";
                    return;
                }
                // Loop through each anomaly and create a new table row
                data.forEach(entry => {
                    let row = `
                        <tr>
                            <td>${entry.timestamp}</td>
                            <td>${entry.user}</td>
                            <td>${entry.action}</td>
                            <td>${entry.file_name}</td>
                            <td>${entry.recipient || "-"}</td>
                        </tr>`;
                    anomalyTable.innerHTML += row;
                });
            })
            .catch(error => {
                // Catch and log any network or fetch errors
                console.error("Error fetching anomalies:", error);
                alert("Failed to fetch anomalies.");
            });
    });
});
