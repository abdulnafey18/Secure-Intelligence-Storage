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
                displayThreats(data.threats);
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

    function displayThreats(threatData) {
        threatLogsTable.innerHTML = "";
        threatData.forEach(threat => {
            let row = `<tr>
                <td>${threat.host}</td>
                <td>${threat.port}</td>
                <td>${threat.service}</td>
                <td style="color: red;">${threat.status}</td>
            </tr>`;
            threatLogsTable.innerHTML += row;
        });
    }
});