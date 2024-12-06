document.getElementById('send-btn').addEventListener('click', sendMessage);
document.getElementById('message').addEventListener('keypress', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

function sendMessage() {
    const chatbox = document.getElementById('chatbox');
    const userInput = document.getElementById('message');
    const message = userInput.value.trim();

    if (message === '') return;

    // Display the user's message
    const userMessage = `<div class="message user"><p>${message}</p></div>`;
    chatbox.innerHTML += userMessage;
    chatbox.scrollTop = chatbox.scrollHeight;

    userInput.value = '';

    // Send the message to the server
    fetch('/chat', {
        method: 'POST',
        body: JSON.stringify({ message }),
        headers: { 'Content-Type': 'application/json' },
    })
        .then(response => response.json())
        .then(data => {
            // Display the bot's response
            const botMessage = `<div class="message bot"><p>${data.reply}</p></div>`;
            chatbox.innerHTML += botMessage;
            chatbox.scrollTop = chatbox.scrollHeight;
        })
        .catch(() => {
            // Display an error message
            const errorMessage = `<div class="message bot"><p>Sorry, there was an issue processing your request.</p></div>`;
            chatbox.innerHTML += errorMessage;
            chatbox.scrollTop = chatbox.scrollHeight;
        });
}

document.addEventListener('DOMContentLoaded', function () {
    const historyList = document.getElementById('history-list');

    // Dummy chat history (replace with API calls)
    const chatHistory = [
        'Session 1 - Inquiry about business permits',
        'Session 2 - Tax filing guidance',
        'Session 3 - Barangay complaint report',
    ];

    // Populate the sidebar with chat history
    function loadChatHistory() {
        if (chatHistory.length > 0) {
            historyList.innerHTML = '';
            chatHistory.forEach((session, index) => {
                const listItem = document.createElement('li');
                listItem.textContent = session;
                listItem.setAttribute('data-session-id', index);
                listItem.addEventListener('click', () => loadSession(index));
                historyList.appendChild(listItem);
            });
        }
    }

    // Load a specific session (future implementation)
    function loadSession(sessionId) {
        const chatbox = document.getElementById('chatbox');
        chatbox.innerHTML = `<div class="message bot"><p>Loading ${chatHistory[sessionId]}...</p></div>`;
        // Add server call logic to load the session
    }

    loadChatHistory(); // Populate chat history on load
});
