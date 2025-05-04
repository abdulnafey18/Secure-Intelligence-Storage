document.addEventListener("DOMContentLoaded", function () {
    const anomalyButton = document.getElementById("anomalyButton");
    const anomalyTable = document.querySelector("#anomalyTable tbody");
    const reportButton = document.getElementById("generateReportButton");

    anomalyButton.addEventListener("click", function () {
        console.log("Checking for file anomalies...");
        fetch("/get_file_anomalies")
            .then(response => response.json())
            .then(data => {
                anomalyTable.innerHTML = "";
                reportButton.disabled = true;
                reportButton.classList.remove("enabled");  // Remove enabled style

                if (!Array.isArray(data)) {
                    console.error("Backend returned error:", data.error || data);
                    anomalyTable.innerHTML = "<tr><td colspan='6'>Server error. Check console.</td></tr>";
                    return;
                }

                if (data.length === 0) {
                    anomalyTable.innerHTML = "<tr><td colspan='6'>No anomalies detected</td></tr>";
                    return;
                }

                reportButton.disabled = false;
                reportButton.classList.add("enabled");  // Add enabled style (green)

                data.forEach(entry => {
                    let row = `
                        <tr>
                            <td>${entry.timestamp}</td>
                            <td>${entry.user}</td>
                            <td>${entry.action}</td>
                            <td>${entry.file_name}</td>
                            <td>${entry.recipient || "-"}</td>
                            <td>${entry.suspicious_score}</td>
                        </tr>`;
                    anomalyTable.innerHTML += row;
                });
            })
            .catch(error => {
                console.error("Error fetching anomalies:", error);
                alert("Failed to fetch anomalies.");
            });
    });
});