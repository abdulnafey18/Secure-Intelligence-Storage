// fetchLogs function to be used for log fetching
function fetchLogs() {
    let logType = document.getElementById("logType").value;
    fetch(`/get_logs/${logType}`)
        .then(response => response.json())
        .then(data => {
            console.log("Fetched Logs:", data);  

            let logDisplay = document.getElementById("logDisplay");
            logDisplay.innerHTML = ""; 

            data.forEach(log => {
                let row = `<tr>
                    <td>${log.timestamp}</td>
                    <td>${log.message}</td>
                    <td>${log.ip || '-'}</td>
                    <td>${log.file_size || '-'}</td>
                </tr>`;
                logDisplay.insertAdjacentHTML("beforeend", row);  
            });
        })
        .catch(error => console.error("Error fetching logs:", error));
}

// Event listener to handle onchange event
document.addEventListener("DOMContentLoaded", () => {
    const logTypeSelect = document.getElementById("logType");
    logTypeSelect.addEventListener("change", fetchLogs);
    
    // Load logs when the page loads
    fetchLogs();
});