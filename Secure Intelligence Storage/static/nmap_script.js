document.addEventListener("DOMContentLoaded", function () {
    const scanButton = document.getElementById("scanButton");
    const scanResultsTable = document.querySelector("#scanResults tbody");
    const threatLogsTable = document.querySelector("#threatLogs tbody");
    // When the scan button is clicked
    scanButton.addEventListener("click", function () {
        console.log("Scan button clicked! Sending request...");

        fetch("/scan_network", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        })
        .then(response => response.json())
        .then(data => {
            console.log("Scan Response Data:", data);
            if (data.status === "success") {
                displayResults(data.results);
                fetchThreatLogs(); // Fetch updated threats
            } else {
                alert("Scan failed: " + data.message);
            }
        })
        .catch(error => {
            console.error("Fetch Error:", error);
            alert("Scan request failed. Check console.");
        });
    });
    // Function to display scan results in the table
    function displayResults(scanData) {
        scanResultsTable.innerHTML = ""; // Clear previous scan results

        scanData.forEach(entry => {
            entry.ports.forEach(portInfo => {
                let row = `<tr>
                    <td>${entry.host}</td>
                    <td>${portInfo.port}</td>
                    <td>${portInfo.state}</td>
                    <td>${portInfo.service}</td>
                </tr>`;
                scanResultsTable.innerHTML += row;
            });
        });
    }
    // Fetch and display updated threat logs from MongoDB
    function fetchThreatLogs() {
        fetch("/get_threat_logs")
        .then(response => response.json())
        .then(data => {
            let tableBody = document.querySelector("#threatLogs tbody");
            tableBody.innerHTML = ""; // Clear previous threat logs

            data.forEach(threat => {
                let row = `
                    <tr>
                        <td>${formatTimestamp(threat.timestamp)}</td>
                        <td>${threat.host}</td>
                        <td>${threat.port}</td>
                        <td>${threat.service}</td>
                        <td>${threat.status}</td>
                        <td>
                            <form method="POST" action="/toggle_ip_block">
                                <input type="hidden" name="ip" value="${threat.host}">
                                <button type="submit" class="block-btn">
                                    ${threat.status === "Blocked" ? "Unblock" : "Block"}
                                </button>
                            </form>
                        </td>
                    </tr>
                `;
                tableBody.innerHTML += row;
            });
        });
    }
    // Format ISO timestamps into readable local format
    function formatTimestamp(timestamp) {
        if (!timestamp) return "N/A";  // Handle missing timestamps

        let date = new Date(timestamp);
        return date.toLocaleString("en-GB", { 
            year: "numeric", 
            month: "short", 
            day: "2-digit", 
            hour: "2-digit", 
            minute: "2-digit", 
            second: "2-digit"
        });
    }

    // Fetch threat logs on page load
    fetchThreatLogs();
});
