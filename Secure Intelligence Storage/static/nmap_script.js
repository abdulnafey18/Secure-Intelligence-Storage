document.addEventListener("DOMContentLoaded", function () {
    const scanButton = document.getElementById("scanButton");
    const scanResultsTable = document.querySelector("#scanResults tbody");
    const threatLogsTable = document.querySelector("#threatLogs tbody");

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
                //  Fetch latest threats separately
                fetchThreatLogs();
            } else {
                alert("Scan failed: " + data.message);
            }
        })
        .catch(error => {
            console.error("Fetch Error:", error);
            alert("Scan request failed. Check console.");
        });
    });

    function displayResults(scanData) {
        scanResultsTable.innerHTML = "";
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

// Fetch threats and populate the table
function fetchThreatLogs() {
    fetch("/get_threat_logs")
    .then(response => response.json())
    .then(data => {
        let tableBody = document.getElementById("threatLogTable");
        tableBody.innerHTML = ""; // Clear existing data

        data.forEach(threat => {
            let row = document.createElement("tr");

            // Check if the IP is already blocked
            let actionButton = `<button onclick="blockIP('${threat.host}')">Block</button>`;
            if (threat.status === "Blocked") {
                actionButton = `<button onclick="unblockIP('${threat.host}')">Unblock</button>`;
            }

            row.innerHTML = `
                <td>${new Date(threat.timestamp).toLocaleString()}</td>
                <td>${threat.host}</td>
                <td>${threat.port}</td>
                <td>${threat.service}</td>
                <td>${threat.status}</td>
                <td>${actionButton}</td> <!-- Block/Unblock Button -->
            `;

            tableBody.appendChild(row);
        });
    });
}

// Block IP function
function blockIP(ip) {
    fetch("/block_ip", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `ip=${ip}`
    }).then(response => response.json()).then(data => {
        alert(data.message);
        fetchThreatLogs(); // Refresh the table
    });
}

// Unblock IP function
function unblockIP(ip) {
    fetch("/unblock_ip", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `ip=${ip}`
    }).then(response => response.json()).then(data => {
        alert(data.message);
        fetchThreatLogs(); // Refresh the table
    });
}

// Load threat logs on page load
document.addEventListener("DOMContentLoaded", fetchThreatLogs);

//  Function to format the timestamp properly
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
});
