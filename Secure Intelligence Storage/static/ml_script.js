document.addEventListener("DOMContentLoaded", function () {
    const anomalyButton = document.getElementById("anomalyButton");
    const anomalyTable = document.querySelector("#anomalyTable tbody");

    anomalyButton.addEventListener("click", function () {
        console.log("Checking for file anomalies...");

        fetch("/get_file_anomalies")
            .then(response => response.json())
            .then(data => {
                anomalyTable.innerHTML = ""; // Clear previous

                if (data.length === 0) {
                    anomalyTable.innerHTML = "<tr><td colspan='5'>No anomalies detected</td></tr>";
                    return;
                }

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
                console.error("Error fetching anomalies:", error);
                alert("Failed to fetch anomalies.");
            });
    });
});