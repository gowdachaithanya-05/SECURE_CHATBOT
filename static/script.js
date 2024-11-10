

const secretKey = CryptoJS.enc.Hex.parse("796F75723136627974656B6579313233");  // "your16bytekey123" in hex

// Function to encrypt a message
function encrypt(message) {
    let iv = CryptoJS.lib.WordArray.random(16);
    let encrypted = CryptoJS.AES.encrypt(message, secretKey, { iv: iv });
    return {
        iv: CryptoJS.enc.Base64.stringify(iv),
        ct: encrypted.ciphertext.toString(CryptoJS.enc.Base64)
    };
}

// Function to decrypt an encrypted message
function decrypt(encMessage) {
    try {
        let iv = CryptoJS.enc.Base64.parse(encMessage.iv);
        let ct = CryptoJS.enc.Base64.parse(encMessage.ct);
        let encrypted = CryptoJS.lib.CipherParams.create({ ciphertext: ct });
        let decrypted = CryptoJS.AES.decrypt(encrypted, secretKey, { iv: iv });
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        console.error('Error during decryption:', e);
        return 'Decryption error';
    }
}

// Function to send a message
function sendMessage() {
    let userMessage = document.getElementById('chat-input').value;
    if (userMessage.trim() === "") return;

    let chatBox = document.getElementById('chat-box');
    let userMessageElement = document.createElement('p');
    userMessageElement.classList.add('user-message');
    userMessageElement.innerHTML = `<strong>You:</strong> ${userMessage}`;
    chatBox.appendChild(userMessageElement);
    chatBox.scrollTop = chatBox.scrollHeight;

    document.getElementById('chat-input').value = "";

    let messages = Array.from(chatBox.getElementsByTagName('p')).map(p => {
        let text = p.innerHTML;
        if (text.startsWith("<strong>You:</strong>")) {
            return {role: "user", content: p.innerText.replace("You: ", "")};
        } else {
            return {role: "assistant", content: p.innerText.replace("Chatbot: ", "")};
        }
    });

    let encUserMessage = encrypt(userMessage);

    console.log("Sending encrypted message:", encUserMessage);  // Debugging statement

    fetch('/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({message: encUserMessage, messages: messages})
    })
    .then(response => response.json())
    .then(data => {
        console.log("Received response:", data);  // Debugging statement
        let botResponse = decrypt(JSON.parse(data.response));
        console.log("Decrypted bot response:", botResponse);  // Debugging statement

        let botMessageElement = document.createElement('p');
        botMessageElement.classList.add('bot-message');
        botMessageElement.innerHTML = `<img src="https://ih1.redbubble.net/image.5009204302.5238/tst,small,845x845-pad,1000x1000,f8f8f8.jpg" class="logo">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ${botResponse}`;
        chatBox.appendChild(botMessageElement);
        chatBox.scrollTop = chatBox.scrollHeight;

        // Check if disappearing messages feature is enabled
        let disappearingEnabled = document.getElementById('disappearing-toggle').checked;

        // Hide user message after 5 seconds
        let userMessageIndex = messages.length - 1;
        let userMessageElement = chatBox.getElementsByTagName('p')[userMessageIndex];
        if (disappearingEnabled && userMessageElement && userMessageElement.classList.contains('user-message')) {
            setTimeout(() => {
                userMessageElement.style.display = 'none';
            }, 5000); // Message disappears after 5 seconds (adjust as needed)
        }

        // Hide bot message after 5 seconds
        if (disappearingEnabled) {
            setTimeout(() => {
                botMessageElement.style.display = 'none';
            }, 5000); // Message disappears after 5 seconds (adjust as needed)
        }
    })
    .catch(error => console.error('Error:', error));
}

// Event listeners for sending messages on button click and Enter key press
document.getElementById('send-button').addEventListener('click', sendMessage);
document.getElementById('chat-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
