function showForm(type) {
    document.getElementById('offensive-form').style.display = type === 'offensive' ? 'block' : 'none';
    document.getElementById('defensive-form').style.display = type === 'defensive' ? 'block' : 'none';
}

function toggleSchedule() {
    let schedule = document.getElementById('schedule');
    schedule.style.display = document.getElementById('scan-type').value === 'recurring' ? 'block' : 'none';
}

function addContainer() {
    let div = document.createElement('div');
    div.className = 'container-id-group';
    div.innerHTML = '<input type="text" placeholder="Container ID" required> <button type="button" class="remove-btn" onclick="removeContainer(this)">-</button>';
    document.getElementById('container-list').appendChild(div);
}

function removeContainer(button) {
    button.parentElement.remove();
}

function submitForm(event, url) {
    event.preventDefault();

    let form = event.target;
    let formData = new FormData();

    let scanName = form.querySelector('input[type="text"]').value;
    formData.append('scan_name', scanName);

    if (form.id === 'defensive-form') {
        let scanType = document.getElementById('scan-type').value;
        formData.append('scan_type', scanType);

        let containerIds = [];
        document.querySelectorAll('#container-list input').forEach(input => {
            containerIds.push(input.value);
        });
        formData.append('container_ids', JSON.stringify(containerIds));
    }

    fetch(url, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) throw new Error('Network response was not ok');
        return response.blob();
    })
    .then(blob => {
        let downloadLink = document.createElement('a');
        let fileURL = URL.createObjectURL(blob);
        downloadLink.href = fileURL;
        downloadLink.download = 'agent.sh';
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        URL.revokeObjectURL(fileURL);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}