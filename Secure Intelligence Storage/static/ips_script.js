function unblockIP(ip = null) {
    if (!ip) {
        ip = document.getElementById("ip_to_unblock").value;
    }
    
    fetch("/unblock_ip", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `ip=${ip}`
    }).then(response => response.json()).then(data => {
        alert(data.message);
        location.reload();
    });
}

// Fetch blocked IPs and populate the table
function fetchBlockedIPs() {
    fetch("/get_blocked_ips")
    .then(response => response.json())
    .then(data => {
        let tableBody = document.getElementById("blockedIpsTable");
        tableBody.innerHTML = ""; // Clear existing data

        data.forEach(ipData => {
            let row = document.createElement("tr");

            row.innerHTML = `
                <td>${ipData.ip}</td>
                <td>${ipData.reason || "Unknown"}</td>
                <td>${ipData.timestamp ? new Date(ipData.timestamp).toLocaleString() : "Unknown"}</td>
                <td><button onclick="unblockIP('${ipData.ip}')">Unblock</button></td>
            `;

            tableBody.appendChild(row);
        });
    });
}

// Fetch blocked IPs on page load
document.addEventListener("DOMContentLoaded", fetchBlockedIPs);

function controlIPS(action) {
    fetch("/control_ips", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `action=${action}`
    }).then(response => response.json()).then(data => {
        alert(data.message);
        location.reload();
    });
}