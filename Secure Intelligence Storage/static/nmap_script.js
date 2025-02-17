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

function fetchThreatLogs() {
    console.log("Fetching latest threat logs...");
    fetch("/get_threat_logs")
        .then(response => response.json())
        .then(data => {
            console.log("Threat Logs Data:", data);
            let tableBody = document.querySelector("#threatLogs tbody");
            tableBody.innerHTML = "";  // Clear previous data

            if (data.length === 0) {
                tableBody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>No threats detected</td></tr>";
                return;
            }

	data.reverse().forEach(threat => {
                let formattedTimestamp = formatTimestamp(threat.timestamp);  //  Format timestamp

                let row = `<tr>
                    <td>${formattedTimestamp}</td>  <!--  Display formatted timestamp -->
                    <td>${threat.host}</td>
                    <td>${threat.port}</td>
                    <td>${threat.service}</td>
                    <td style="color: red;">${threat.status}</td>
                </tr>`;
                tableBody.innerHTML += row;
            });
        })
        .catch(error => console.error("Error fetching threat logs:", error));
}

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
